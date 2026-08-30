package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/bbs"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func bbsClient(t *testing.T, keys *bbsKeyPair) *Client {
	t.Helper()
	tracer, err := trace.NewForTesting(context.Background(), "test", logger.NewSimple("trace"))
	if err != nil {
		t.Fatalf("tracer: %v", err)
	}
	return &Client{
		log:     logger.NewSimple("test"),
		tracer:  tracer,
		bbsKeys: keys,
		cfg: &model.Cfg{
			Issuer: &model.Issuer{
				JWTAttribute: model.JWTAttribute{Issuer: "https://issuer.example.com"},
				BBS:          &model.BBSConfig{},
			},
		},
	}
}

// An issuer with no BBS key must say so rather than sign with a zero key.
// The alternative is a credential that verifies against nothing, discovered
// by the holder at presentation time.
func TestMakeJWPWithoutAConfiguredKey(t *testing.T) {
	_, err := bbsClient(t, nil).MakeJWP(context.Background(), &CreateJWPRequest{
		Commitment: []byte{1, 2, 3},
		VCT:        "urn:example:pid",
	})
	if err == nil {
		t.Fatal("an unconfigured issuer must refuse to issue")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("the error should say the format is unconfigured, got: %v", err)
	}
}

// Both are things the signature covers and the credential cannot be built
// without: there is nothing to blind-sign without a commitment, and the type
// is stamped into the header a verifier reads back.
func TestMakeJWPRequiresCommitmentAndVCT(t *testing.T) {
	c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})

	for _, tc := range []struct {
		name string
		req  *CreateJWPRequest
	}{
		{"no commitment", &CreateJWPRequest{VCT: "urn:example:pid"}},
		{"no vct", &CreateJWPRequest{Commitment: []byte{1, 2, 3}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.MakeJWP(context.Background(), tc.req); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
}

// Reaching the signer without a registry means issuing a credential that can
// never be revoked. That is a worse outcome than a failed issuance, so the
// check comes before any signing.
func TestMakeJWPRequiresARegistry(t *testing.T) {
	c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})

	_, err := c.MakeJWP(context.Background(), &CreateJWPRequest{
		Commitment: []byte{1, 2, 3},
		VCT:        "urn:example:pid",
	})
	if err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("issuance without a registry must fail loudly, got: %v", err)
	}
}

// A status list entry is consumed before anything is signed, and it is never
// handed back. An issuer configured with BBS keys but built without
// `-tags bbsnative` would therefore burn one registry entry per request while
// never issuing a credential - a slow leak in the revocation list rather than
// a visible failure. The availability check has to come first.
func TestMakeJWPDoesNotConsumeAStatusEntryWithoutNativeSupport(t *testing.T) {
	if bbs.Available() {
		t.Skip("this is the untagged build's failure mode; native support is compiled in")
	}
	c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})
	registry := &mockRegistryClient{}
	c.registryClient = registry

	_, err := c.MakeJWP(context.Background(), &CreateJWPRequest{
		Commitment: []byte{1, 2, 3},
		VCT:        "urn:example:pid",
	})
	if err == nil {
		t.Fatal("an issuer with no native support must refuse to issue")
	}
	if got := grpcstatus.Code(err); got != codes.Unimplemented {
		t.Fatalf("want codes.Unimplemented, got %v (%v)", got, err)
	}
	if registry.index != 0 {
		t.Fatalf("a refused issuance must consume no status entry, %d consumed", registry.index)
	}
}

// Same argument as the availability check, one layer up: `holder_pointers` is
// entirely caller-controlled, and a list that cannot possibly be signed must
// not cost a revocation entry to discover.
func TestMakeJWPRejectsTooManyHolderPointersWithoutConsumingAStatusEntry(t *testing.T) {
	c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})
	registry := &mockRegistryClient{}
	c.registryClient = registry

	pointers := make([]string, bbs.MaxMessages+1)
	for i := range pointers {
		pointers[i] = fmt.Sprintf("/claim%d", i)
	}

	_, err := c.MakeJWP(context.Background(), &CreateJWPRequest{
		Commitment:     []byte{1, 2, 3},
		VCT:            "urn:example:pid",
		HolderPointers: pointers,
	})
	if err == nil {
		t.Fatal("a pointer list over the limit must be rejected")
	}
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("want codes.InvalidArgument, got %v (%v)", got, err)
	}
	if registry.index != 0 {
		t.Fatalf("a refused issuance must consume no status entry, %d consumed", registry.index)
	}
}

// The issuer's claims become the credential's claim map, so anything that is
// not a JSON object cannot be signed - and the same "never handed back"
// argument applies: discovering it inside the native signer costs a status
// list entry.
func TestMakeJWPRejectsNonObjectDocumentDataWithoutConsumingAStatusEntry(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"array", `["not","an","object"]`},
		{"string", `"nope"`},
		{"number", `7`},
		{"null", `null`},
		{"not json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})
			registry := &mockRegistryClient{}
			c.registryClient = registry

			_, err := c.MakeJWP(context.Background(), &CreateJWPRequest{
				Commitment:   []byte{1, 2, 3},
				VCT:          "urn:example:pid",
				DocumentData: []byte(tc.data),
			})
			if err == nil {
				t.Fatalf("accepted %s as document_data", tc.name)
			}
			if got := grpcstatus.Code(err); got != codes.InvalidArgument {
				t.Fatalf("want codes.InvalidArgument, got %v (%v)", got, err)
			}
			if registry.index != 0 {
				t.Fatalf("a refused issuance must consume no status entry, %d consumed", registry.index)
			}
		})
	}
}

// Revocation status and issuer identity go in the header, not the claims.
//
// A claim is one of the signed messages and therefore selectively
// disclosable, and revocation a holder can decline to reveal is not
// revocation at all. The same argument covers `iss`: a credential whose
// issuer could be withheld is one no verifier can attribute.
func TestBBSIssuerHeaderCarriesWhatMustNotBeHidden(t *testing.T) {
	c := bbsClient(t, &bbsKeyPair{secret: []byte{1}, public: []byte{2}})

	raw, err := c.bbsIssuerHeader(&apiv1_registry.TokenStatusListAddStatusReply{
		Index:         42,
		StatusListUri: "https://issuer.example.com/statuslists/1",
	})
	if err != nil {
		t.Fatalf("bbsIssuerHeader: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("header is not a JSON object: %v", err)
	}

	if header["iss"] != "https://issuer.example.com" {
		t.Fatalf("iss = %v, want the configured issuer", header["iss"])
	}
	iat, iatOK := header["iat"].(float64)
	exp, expOK := header["exp"].(float64)
	if !iatOK || !expOK {
		t.Fatalf("iat/exp missing or not numeric: %v", header)
	}
	// The default applies when DefaultValidity is unset, rather than
	// producing a credential that expired at the moment it was issued.
	if exp <= iat {
		t.Fatalf("exp (%v) must be after iat (%v)", exp, iat)
	}

	statusList, ok := header["status"].(map[string]any)["status_list"].(map[string]any)
	if !ok {
		t.Fatalf("no status.status_list in header: %v", header)
	}
	if statusList["idx"] != float64(42) {
		t.Fatalf("status idx = %v, want the allocated index", statusList["idx"])
	}
	if statusList["uri"] != "https://issuer.example.com/statuslists/1" {
		t.Fatalf("status uri = %v, want the allocated uri", statusList["uri"])
	}
}

// --- key loading ---------------------------------------------------------

func writeKeyFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestInitBBSKeys(t *testing.T) {
	dir := t.TempDir()

	t.Run("absent config leaves the format off", func(t *testing.T) {
		c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{}}
		if err := c.initBBSKeys(); err != nil {
			t.Fatalf("an issuer that does not offer BBS must start: %v", err)
		}
		if c.bbsKeys != nil {
			t.Fatal("no keys should have been loaded")
		}
	})

	t.Run("a trailing newline is not a broken key", func(t *testing.T) {
		// Every editor and every shell redirect leaves one behind;
		// rejecting it would be a needless trap.
		c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{BBS: &model.BBSConfig{
			SecretKeyPath: writeKeyFile(t, dir, "ok.sk", "AQIDBAU\n"),
			PublicKeyPath: writeKeyFile(t, dir, "ok.pk", "BgcICQo\n"),
		}}}}
		if err := c.initBBSKeys(); err != nil {
			t.Fatalf("initBBSKeys: %v", err)
		}
		if string(c.bbsKeys.secret) != string([]byte{1, 2, 3, 4, 5}) {
			t.Fatalf("secret = %v, want the decoded bytes", c.bbsKeys.secret)
		}
		if string(c.bbsKeys.public) != string([]byte{6, 7, 8, 9, 10}) {
			t.Fatalf("public = %v, want the decoded bytes", c.bbsKeys.public)
		}
	})

	// A configured-but-broken key means the operator asked for the format
	// and it does not work. Starting anyway would turn one startup failure
	// into a failure per issuance request.
	for _, tc := range []struct{ name, secret, public string }{
		{"secret not base64url", "!!!!", "BgcICQo"},
		{"public not base64url", "AQIDBAU", "!!!!"},
		{"empty secret", "", "BgcICQo"},
		{"standard base64 alphabet", "a+/b", "BgcICQo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{BBS: &model.BBSConfig{
				SecretKeyPath: writeKeyFile(t, t.TempDir(), "k.sk", tc.secret),
				PublicKeyPath: writeKeyFile(t, t.TempDir(), "k.pk", tc.public),
			}}}}
			if err := c.initBBSKeys(); err == nil {
				t.Fatal("a broken key must fail startup, not one request at a time")
			}
		})
	}

	t.Run("a missing file fails startup", func(t *testing.T) {
		c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Issuer: &model.Issuer{BBS: &model.BBSConfig{
			SecretKeyPath: filepath.Join(dir, "does-not-exist.sk"),
			PublicKeyPath: writeKeyFile(t, dir, "present.pk", "BgcICQo"),
		}}}}
		if err := c.initBBSKeys(); err == nil {
			t.Fatal("a missing key file must fail startup")
		}
	})
}
