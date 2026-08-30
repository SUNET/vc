package apiv1

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// The issuer refuses claims with nothing in them - bbs.ValidateDocumentData
// requires at least one, matching the crate's own "no claims to sign" vector
// - so these tests use a minimal real claim set rather than `{}`, which no
// issuance could ever carry.
var validBBSDocumentData = []byte(`{"given_name":"Ada"}`)

// recordingIssuerClient captures the MakeJWP request the APIGW builds.
//
// It embeds the interface rather than implementing all seven methods: only
// MakeJWP is exercised here, and a nil-panic on any other call is a louder
// failure than a silent stub returning a zero value.
type recordingIssuerClient struct {
	apiv1_issuer.IssuerServiceClient
	got   *apiv1_issuer.MakeJWPRequest
	reply *apiv1_issuer.MakeJWPReply
	err   error
}

func (r *recordingIssuerClient) MakeJWP(_ context.Context, in *apiv1_issuer.MakeJWPRequest, _ ...grpc.CallOption) (*apiv1_issuer.MakeJWPReply, error) {
	r.got = in
	if r.err != nil {
		return nil, r.err
	}
	return r.reply, nil
}

func bbsTestClient(t *testing.T, issuer *recordingIssuerClient) *Client {
	t.Helper()
	return &Client{
		log:          logger.NewSimple("test"),
		issuerClient: issuer,
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"pid_jwp": {
						Format: "jwp",
						VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:jwp:1"},
					},
					"no_vct": {Format: "jwp"},
				},
			},
		},
	}
}

func bbsRequest() *openid4vci.CredentialRequest {
	return &openid4vci.CredentialRequest{
		CredentialConfigurationID: "pid_jwp",
		BBSCommitment:             "AQIDBAU",
		BBSCommittedClaims:        []string{"/device_pin_hash"},
	}
}

// The wallet's commitment must reach the issuer, decoded, with the pointers
// and the vct alongside it. This is the join the whole format depends on:
// the issuer signs a commitment it did not make, places claims it cannot
// see, and stamps a type into a header a verifier reads back.
func TestIssueBBSPassesTheCommitmentThrough(t *testing.T) {
	issuer := &recordingIssuerClient{
		reply: &apiv1_issuer.MakeJWPReply{
			Credentials: []*apiv1_issuer.Credential{{Credential: "hdr.payloads.proof"}},
		},
	}
	c := bbsTestClient(t, issuer)

	credentials, err := c.issueBBS(context.Background(), "pid_jwp", []byte(`{"given_name":"Alice"}`), "", bbsRequest())
	if err != nil {
		t.Fatalf("issueBBS: %v", err)
	}

	if issuer.got == nil {
		t.Fatal("the issuer was never called")
	}
	// Decoded, not forwarded as the base64url string it arrived as - the
	// issuer's signing input is bytes.
	if want := []byte{1, 2, 3, 4, 5}; string(issuer.got.Commitment) != string(want) {
		t.Fatalf("commitment = %v, want %v", issuer.got.Commitment, want)
	}
	if len(issuer.got.HolderPointers) != 1 || issuer.got.HolderPointers[0] != "/device_pin_hash" {
		t.Fatalf("holder pointers = %v, want [/device_pin_hash]", issuer.got.HolderPointers)
	}
	if issuer.got.Vct != "urn:eudi:pid:jwp:1" {
		t.Fatalf("vct = %q, want the scope's own vct", issuer.got.Vct)
	}

	// One credential, and the JWP verbatim. Unlike mso_mdoc there is no
	// base64url wrapper: Compact Serialization is already printable, and
	// wrapping it would leave the wallet decoding a layer that is not there.
	if len(credentials) != 1 {
		t.Fatalf("got %d credentials, want exactly 1", len(credentials))
	}
	if credentials[0].Credential != "hdr.payloads.proof" {
		t.Fatalf("credential = %q, want the JWP unwrapped", credentials[0].Credential)
	}
}

// Key binding comes from the wallet's assertion, never from the request's
// proofs. Those are ECDSA proof-of-possession keys carrying c_nonce
// freshness and are present either way; the key binding keys are BLS Schnorr
// keys sealed inside the commitment. Reading the proofs instead would bind
// every BBS credential that carried a proof, whether or not one was
// committed.
func TestIssueBBSTakesKeyBindingFromTheCommitmentAssertion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		asserted bool
	}{
		{"unbound", false},
		{"bound", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &recordingIssuerClient{
				reply: &apiv1_issuer.MakeJWPReply{
					Credentials: []*apiv1_issuer.Credential{{Credential: "a.b.c"}},
				},
			}
			c := bbsTestClient(t, issuer)

			req := bbsRequest()
			req.BBSKeyBinding = tc.asserted
			// A proof is present in both cases, which is the point.
			req.Proof = &openid4vci.Proof{ProofType: "jwt", JWT: "not.a.real.jwt"}

			if _, err := c.issueBBS(context.Background(), "pid_jwp", validBBSDocumentData, "", req); err != nil {
				t.Fatalf("issueBBS: %v", err)
			}
			if issuer.got.KeyBinding != tc.asserted {
				t.Fatalf("key_binding = %v, want %v (it must follow the commitment assertion, not the proof)",
					issuer.got.KeyBinding, tc.asserted)
			}
		})
	}
}

// A jwp request without a commitment cannot be completed at all: there is
// nothing to sign over. Failing here, naming the member, beats reaching the
// signer with an empty commitment.
func TestIssueBBSRefusesWithoutACommitment(t *testing.T) {
	issuer := &recordingIssuerClient{}
	c := bbsTestClient(t, issuer)

	req := bbsRequest()
	req.BBSCommitment = ""

	_, err := c.issueBBS(context.Background(), "pid_jwp", validBBSDocumentData, "", req)
	if err == nil {
		t.Fatal("a jwp issuance without bbs_commitment must fail")
	}
	if !strings.Contains(err.Error(), "bbs_commitment") {
		t.Fatalf("the error should name the missing member, got: %v", err)
	}
	if issuer.got != nil {
		t.Fatal("the issuer must not be called for a request that cannot be completed")
	}
}

// The type is signed into the credential's header and read back by every
// verifier, so an untyped credential is one nothing can check. A scope
// configured without a vct is a configuration error, not a credential to
// issue with an empty type.
func TestIssueBBSRefusesAScopeWithNoVCT(t *testing.T) {
	issuer := &recordingIssuerClient{}
	c := bbsTestClient(t, issuer)

	_, err := c.issueBBS(context.Background(), "no_vct", validBBSDocumentData, "", bbsRequest())
	if err == nil {
		t.Fatal("a scope with no vct must fail rather than issue an untyped credential")
	}
	if issuer.got != nil {
		t.Fatal("the issuer must not be called")
	}
}

func TestIssueBBSRejectsAnUnknownScope(t *testing.T) {
	issuer := &recordingIssuerClient{}
	c := bbsTestClient(t, issuer)

	if _, err := c.issueBBS(context.Background(), "not_configured", validBBSDocumentData, "", bbsRequest()); err == nil {
		t.Fatal("an unconfigured scope must fail")
	}
}
