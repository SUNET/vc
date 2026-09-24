package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
		Key:                 key,
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

// TestStatusServiceKey_DefaultsToIssuerKey checks requirement #2 ("default
// to the issuer signing key"): with no explicit
// issuer.status_service.key_config, a usable P-256 issuer signing key is
// reused as-is.
func TestStatusServiceKey_DefaultsToIssuerKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := &Client{privateKey: key, cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	got, err := c.statusServiceKey(&model.StatusServiceConfig{})
	if err != nil {
		t.Fatalf("statusServiceKey: %v", err)
	}
	if got != key {
		t.Fatal("want the issuer's own P-256 key reused as-is")
	}
}

// TestStatusServiceKey_RefusesNonP256IssuerKey checks that an issuer whose
// own signing key cannot be defaulted (not EC, or EC but not P-256) fails
// loudly and names the fix, rather than silently disabling the feature.
func TestStatusServiceKey_RefusesNonP256IssuerKey(t *testing.T) {
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := &Client{privateKey: p384Key, cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	_, err = c.statusServiceKey(&model.StatusServiceConfig{})
	if err == nil {
		t.Fatal("a non-P-256 issuer key must not be defaulted silently")
	}
	if !strings.Contains(err.Error(), "status_service.key_config") {
		t.Fatalf("error should point at the fix (issuer.status_service.key_config), got: %v", err)
	}
}

// TestStatusServiceKey_RefusesHSMBackedIssuerKey checks the PKCS#11 case
// specifically: the issuer's own key is not a raw *ecdsa.PrivateKey at all
// (simulated here by any non-ecdsa value, standing in for a PKCS#11-backed
// crypto.Signer wrapper), and must be refused the same way.
func TestStatusServiceKey_RefusesHSMBackedIssuerKey(t *testing.T) {
	c := &Client{privateKey: "not-a-real-key", cfg: &model.Cfg{Issuer: &model.Issuer{}}}

	_, err := c.statusServiceKey(&model.StatusServiceConfig{})
	if err == nil {
		t.Fatal("an HSM-backed (non-raw-key) issuer key must not be defaulted silently")
	}
}
