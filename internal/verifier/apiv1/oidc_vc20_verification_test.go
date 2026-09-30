package apiv1

import (
	"context"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"

	"github.com/stretchr/testify/require"
)

const unsignedW3CPresentation = `{
	"@context": "https://www.w3.org/ns/credentials/v2",
	"type": ["VerifiablePresentation"],
	"holder": "did:example:holder",
	"verifiableCredential": [{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "name": "Alice"}
	}]
}`

// TestVerifyVC20ForOIDCRefusesAnUnsignedDocument: the OIDC direct-post path
// verifies nothing for any format, and that is not a licence to add another
// unverified one. Making W3C usable there means an arbitrary JSON-LD
// document would otherwise have its credentialSubject mapped into the
// session, with nothing checking who signed it.
//
// A document with no proof at all is the cheapest thing an attacker posts,
// so it is the case worth pinning.
func TestVerifyVC20ForOIDCRefusesAnUnsignedDocument(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	session := &cache.AuthorizationContext{
		Nonce:    "session-nonce",
		ClientID: "x509_san_dns:verifier.example.com",
		Scopes:   []string{"pid"},
	}

	err := client.verifyVC20ForOIDC(t.Context(), session, unsignedW3CPresentation)
	require.Error(t, err, "an unsigned presentation must not reach claim extraction")
}

// TestVerifyVC20ForOIDCNeedsASession keeps the guard from being skippable by
// arriving without one.
func TestVerifyVC20ForOIDCNeedsASession(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	require.Error(t, client.verifyVC20ForOIDC(t.Context(), nil, unsignedW3CPresentation))
}

// TestVerifyVC20ForOIDCNeedsAKeyResolvingEvaluator: without one there is no
// way to check a proof, and "cannot verify" has to mean refuse.
func TestVerifyVC20ForOIDCNeedsAKeyResolvingEvaluator(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = evaluatorWithoutKeyResolution{}

	err := client.verifyVC20ForOIDC(t.Context(), &cache.AuthorizationContext{Nonce: "n", ClientID: "c"}, unsignedW3CPresentation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key-resolving")
}

// TestVerifyVC20ForOIDCLetsANonW3CResponseThrough: a DCQL response is a JSON
// object too, so a detector that only asks "does this look like JSON" calls
// the ENVELOPE a W3C credential - and a conformant direct-post carrying
// SD-JWTs would fail W3C verification on the wrapper without its contents
// ever being looked at.
func TestVerifyVC20ForOIDCLetsANonW3CResponseThrough(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	session := &cache.AuthorizationContext{Nonce: "n", ClientID: "c", Scopes: []string{"pid"}}

	for name, token := range map[string]string{
		"a DCQL envelope of SD-JWTs": `{"pid": ["eyJhbGciOiJFUzI1NiJ9.x.y~"]}`,
		"a bare SD-JWT":              "eyJhbGciOiJFUzI1NiJ9.x.y~",
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, client.verifyVC20ForOIDC(t.Context(), session, token),
				"a response carrying no W3C document is not this guard's business")
		})
	}
}

// evaluatorWithoutKeyResolution is a TrustEvaluator that does NOT implement
// trust.KeyResolver, which AllowAllEvaluator does.
type evaluatorWithoutKeyResolution struct{}

func (evaluatorWithoutKeyResolution) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	return &trustapi.TrustDecision{Trusted: true}, nil
}

func (evaluatorWithoutKeyResolution) SupportsKeyType(_ trust.KeyType) bool { return true }

// TestProcessDirectPostRefusesAnUnverifiedW3CToken is the call-site half:
// the guard only matters if ProcessDirectPost installs it before extracting
// claims.
//
// An unsigned presentation posted to this endpoint must be refused. Without
// the gate it parses fine - the claims extractor reads credentialSubject
// happily - and Alice's name lands in the OIDC session.
func TestProcessDirectPostRefusesAnUnverifiedW3CToken(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	const sessionID = "session-w3c-unverified"
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, &cache.AuthorizationContext{
		SessionID:   sessionID,
		Status:      cache.SessionStatusPending,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
		ClientID:    "test-client",
		RedirectURI: "https://client.example.com/callback",
		Scopes:      []string{"openid", "pid"},
		State:       sessionID,
		Nonce:       "session-nonce",
	}))

	resp, err := client.ProcessDirectPost(ctx, &DirectPostRequest{
		State:   sessionID,
		VPToken: unsignedW3CPresentation,
	})
	require.Error(t, err, "an unsigned W3C presentation must not be accepted")
	require.ErrorIs(t, err, ErrInvalidVP)
	require.Nil(t, resp)
}
