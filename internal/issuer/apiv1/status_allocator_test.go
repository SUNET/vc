package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/statusserviceclient"
)

// TestAllocateOrDegrade_NoAllocatorConfigured checks the "feature is a
// no-op when unset" case at the allocateOrDegrade level: an issuer with
// neither the registry nor the external status service configured gets a
// plain error, not a nil allocation mistaken for success.
func TestAllocateOrDegrade_NoAllocatorConfigured(t *testing.T) {
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	alloc, err := c.allocateOrDegrade(context.Background())
	if err == nil {
		t.Fatal("want an error when no status allocator is configured")
	}
	if alloc != nil {
		t.Fatalf("want a nil allocation on error, got %+v", alloc)
	}
}

// TestAllocateOrDegrade_RegistryFailureAlwaysHardFails confirms this is a
// true no-op for existing (registry-only) deployments: a registry failure
// is always returned as an error, regardless of what
// Issuer.StatusService.DegradedMode might say - because the external
// status service isn't configured at all here, DegradedMode does not even
// apply.
func TestAllocateOrDegrade_RegistryFailureAlwaysHardFails(t *testing.T) {
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{
		// Present but irrelevant: StatusService is nil, so this is a
		// registry-only configuration and DegradedMode must not be
		// consulted.
	}}}
	setRegistry(c, failingRegistry{})

	alloc, err := c.allocateOrDegrade(context.Background())
	if err == nil {
		t.Fatal("a registry failure must be a hard error, not a no-op")
	}
	if alloc != nil {
		t.Fatalf("want a nil allocation on error, got %+v", alloc)
	}
}

// newFailingExternalClient starts a real statusserviceclient.Client against
// an httptest.Server that always fails, so allocateOrDegrade's external
// branch is exercised against a genuine (if permanently broken) HTTP round
// trip rather than a hand-rolled fake statusAllocator - the same principle
// TestAllocateOrDegrade_RegistryFailureAlwaysHardFails applies to the
// registry side.
func newFailingExternalClient(t *testing.T) *statusserviceclient.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	client, err := statusserviceclient.New(statusserviceclient.Config{
		IngestionURL:        server.URL,
		ASURL:               server.URL,
		IssuerID:            "https://issuer.example.org",
		Signer:              pki.NewKeyMaterialSigner(&pki.KeyMaterial{PrivateKey: key, SigningMethod: jwt.SigningMethodES256}),
		PoolSize:            1,
		RetryInitialBackoff: time.Millisecond,
		RetryMaxBackoff:     5 * time.Millisecond,
		TakeFallbackTimeout: 100 * time.Millisecond,
		RefillInterval:      time.Hour, // don't let the background loop interfere with call counts
	}, nil)
	if err != nil {
		t.Fatalf("statusserviceclient.New: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

// TestAllocateOrDegrade_ExternalDegradedModeProceed checks the default
// degraded_mode ("proceed"): when the external status service is
// configured but unreachable, allocateOrDegrade returns (nil, nil) rather
// than an error, so the caller issues the credential without a status
// claim.
func TestAllocateOrDegrade_ExternalDegradedModeProceed(t *testing.T) {
	client := newFailingExternalClient(t)
	c := &Client{
		log:                 logger.NewSimple("test"),
		cfg:                 &model.Cfg{Issuer: &model.Issuer{StatusService: &model.StatusServiceConfig{IngestionURL: "set", DegradedMode: "proceed"}}},
		statusServiceClient: client,
		statusAllocator:     &externalStatusAllocator{client: client, log: logger.NewSimple("test")},
	}

	alloc, err := c.allocateOrDegrade(context.Background())
	if err != nil {
		t.Fatalf("degraded_mode=proceed must not return an error, got %v", err)
	}
	if alloc != nil {
		t.Fatalf("want a nil allocation (issue without a status claim), got %+v", alloc)
	}
}

// TestAllocateOrDegrade_ExternalDegradedModeFail checks the "fail" mode:
// the same unreachable external status service, but now the caller should
// see the error and refuse to issue.
func TestAllocateOrDegrade_ExternalDegradedModeFail(t *testing.T) {
	client := newFailingExternalClient(t)
	c := &Client{
		log:                 logger.NewSimple("test"),
		cfg:                 &model.Cfg{Issuer: &model.Issuer{StatusService: &model.StatusServiceConfig{IngestionURL: "set", DegradedMode: "fail"}}},
		statusServiceClient: client,
		statusAllocator:     &externalStatusAllocator{client: client, log: logger.NewSimple("test")},
	}

	alloc, err := c.allocateOrDegrade(context.Background())
	if err == nil {
		t.Fatal("degraded_mode=fail must return an error when the external service is unreachable")
	}
	if alloc != nil {
		t.Fatalf("want a nil allocation on error, got %+v", alloc)
	}
}

// opaqueSigner stands in for a PKCS#11-backed key: a public key and a Sign
// method, with the private half unreachable through the interface. That is
// the point - possession is demonstrated by signing, not by handing over
// bytes.
type opaqueSigner struct {
	pub *ecdsa.PublicKey
	alg string
}

func (o *opaqueSigner) Sign(context.Context, []byte) ([]byte, error) {
	return []byte("signature"), nil
}
func (o *opaqueSigner) Algorithm() string { return o.alg }
func (o *opaqueSigner) KeyID() string     { return "test-key" }
func (o *opaqueSigner) PublicKey() any    { return o.pub }

func newOpaqueSigner(t *testing.T, curve elliptic.Curve, alg string) *opaqueSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &opaqueSigner{pub: &key.PublicKey, alg: alg}
}

// Requirement #2 ("default to the issuer signing key"): with no explicit
// issuer.status_service.key_config, the issuer's own signer is reused.
func TestStatusServiceSigner_DefaultsToIssuerSigner(t *testing.T) {
	signer := newOpaqueSigner(t, elliptic.P256(), "ES256")
	c := &Client{signer: signer, cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	got, err := c.statusServiceSigner(&model.StatusServiceConfig{})
	if err != nil {
		t.Fatalf("statusServiceSigner: %v", err)
	}
	if got != pki.Signer(signer) {
		t.Fatal("want the issuer's own signer reused as-is")
	}
}

// An HSM-backed key must be ACCEPTED. The assertion proves possession by
// producing a signature, which is exactly what a PKCS#11 device does, and
// nothing in this path needs the private half. An earlier version refused
// it because HSM key material "never leaves the device" - true, and beside
// the point.
func TestStatusServiceSigner_AcceptsAnHSMBackedKey(t *testing.T) {
	signer := newOpaqueSigner(t, elliptic.P256(), "ES256")
	c := &Client{signer: signer, cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	if _, err := c.statusServiceSigner(&model.StatusServiceConfig{}); err != nil {
		t.Fatalf("an HSM-backed P-256 signer must be usable: %v", err)
	}
}

// ES256 on P-256 is still required, because that is what the status
// service's AS verifies - and the error has to name the fix rather than
// silently disable the feature.
func TestStatusServiceSigner_RefusesWhatCannotSignES256(t *testing.T) {
	for _, tt := range []struct {
		name   string
		signer *opaqueSigner
	}{
		{"wrong curve", newOpaqueSigner(t, elliptic.P384(), "ES256")},
		{"wrong algorithm", newOpaqueSigner(t, elliptic.P256(), "RS256")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{signer: tt.signer, cfg: &model.Cfg{Issuer: &model.Issuer{}}}

			_, err := c.statusServiceSigner(&model.StatusServiceConfig{})
			if err == nil {
				t.Fatal("must not be defaulted silently")
			}
			if !strings.Contains(err.Error(), "status_service.key_config") {
				t.Fatalf("error should point at the fix, got: %v", err)
			}
		})
	}
}

// The mdoc and VC 2.0 paths have always been best-effort about status
// entries - neither format requires one - but `degraded_mode: fail` is an
// operator asking for issuance to be REFUSED rather than produce something
// unrevocable. Honouring that only in the SD-JWT/BBS paths would make the
// setting quietly depend on which credential format was requested, so
// allocateOptionalStatus routes the external backend through
// allocateOrDegrade while keeping the registry best-effort.

func TestAllocateOptionalStatus_NoAllocatorIsNotAnError(t *testing.T) {
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	alloc, err := c.allocateOptionalStatus(context.Background(), "mdoc")
	if err != nil {
		t.Fatalf("an unconfigured allocator must not fail issuance, got %v", err)
	}
	if alloc != nil {
		t.Fatalf("want no allocation, got %+v", alloc)
	}
}

func TestAllocateOptionalStatus_ExternalDegradedModeFailRefuses(t *testing.T) {
	client := newFailingExternalClient(t)
	c := &Client{
		log:                 logger.NewSimple("test"),
		cfg:                 &model.Cfg{Issuer: &model.Issuer{StatusService: &model.StatusServiceConfig{IngestionURL: "set", DegradedMode: "fail"}}},
		statusServiceClient: client,
		statusAllocator:     &externalStatusAllocator{client: client, log: logger.NewSimple("test")},
	}

	for _, format := range []string{"mdoc", "vc20"} {
		t.Run(format, func(t *testing.T) {
			alloc, err := c.allocateOptionalStatus(context.Background(), format)
			if err == nil {
				t.Fatal("degraded_mode=fail must refuse the issuance, not issue without a status claim")
			}
			if alloc != nil {
				t.Fatalf("want a nil allocation on error, got %+v", alloc)
			}
		})
	}
}

func TestAllocateOptionalStatus_ExternalDegradedModeProceedIssues(t *testing.T) {
	client := newFailingExternalClient(t)
	c := &Client{
		log:                 logger.NewSimple("test"),
		cfg:                 &model.Cfg{Issuer: &model.Issuer{StatusService: &model.StatusServiceConfig{IngestionURL: "set", DegradedMode: "proceed"}}},
		statusServiceClient: client,
		statusAllocator:     &externalStatusAllocator{client: client, log: logger.NewSimple("test")},
	}

	alloc, err := c.allocateOptionalStatus(context.Background(), "mdoc")
	if err != nil {
		t.Fatalf("degraded_mode=proceed must still issue, got %v", err)
	}
	if alloc != nil {
		t.Fatalf("want a nil allocation, got %+v", alloc)
	}
}

// The registry backend keeps the behaviour these paths always had: a failed
// allocation is logged and the credential issued anyway. degraded_mode is an
// external-service setting and must not start governing the registry.
func TestAllocateOptionalStatus_RegistryStaysBestEffort(t *testing.T) {
	c := &Client{
		log:             logger.NewSimple("test"),
		cfg:             &model.Cfg{Issuer: &model.Issuer{}},
		statusAllocator: &failingAllocator{},
	}

	alloc, err := c.allocateOptionalStatus(context.Background(), "vc20")
	if err != nil {
		t.Fatalf("registry failures must stay best-effort here, got %v", err)
	}
	if alloc != nil {
		t.Fatalf("want no allocation, got %+v", alloc)
	}
}

// failingAllocator stands in for a registry allocator whose backend is down.
type failingAllocator struct{}

func (f *failingAllocator) Allocate(context.Context) (*statusAllocation, error) {
	return nil, fmt.Errorf("registry unavailable")
}
func (f *failingAllocator) Invalidate(context.Context, *statusAllocation) {}
