package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticKeyEvaluator is a trust evaluator that can also resolve one
// verification method, which is what W3C Data Integrity needs and what
// AllowAllEvaluator deliberately cannot do without a PDP.
type staticKeyEvaluator struct {
	key crypto.PublicKey
}

func (e *staticKeyEvaluator) Evaluate(context.Context, *trust.EvaluationRequest) (*trust.TrustDecision, error) {
	return &trust.TrustDecision{Trusted: true}, nil
}
func (e *staticKeyEvaluator) SupportsKeyType(trust.KeyType) bool { return true }
func (e *staticKeyEvaluator) ResolveKey(context.Context, string) (crypto.PublicKey, error) {
	return e.key, nil
}

// TestVerificationDirectPostW3C drives a real signed W3C VC 2.0 credential
// through the verifier: minted with a Data Integrity proof, returned as the
// vp_token of an encrypted direct_post, and verified through the same switch
// SD-JWT and mdoc go through.
//
// Before this branch existed, detectCredentialFormat returned FormatUnknown
// for JSON-LD and the default case rejected it - the credential reached the
// wallet and failed only on presentation.
func TestVerificationDirectPostW3C(t *testing.T) {
	ctx := t.Context()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerHandler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20SignerConfig(&openid4vp.VC20SignerConfig{
			PrivateKey:         issuerKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		}),
	)
	require.NoError(t, err)

	created, err := issuerHandler.CreateCredential(ctx, &openid4vp.VC20CreateRequest{
		Types:   []string{"UniversityDegreeCredential"},
		Subject: map[string]any{"id": "did:example:subject", "degree": "Master of Science"},
	})
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = &staticKeyEvaluator{key: &issuerKey.PublicKey}

	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
	require.NoError(t, err)
	client.openid4vp = openid4vpClient

	notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	require.NoError(t, err)
	client.notify = notifyService

	const (
		kid   = "w3c-ephemeral-kid"
		state = "w3c-state"
		scope = "diploma"
	)
	_, ephemeralPubJWK, err := client.openid4vp.EphemeralKeyCache.GenerateAndStore(kid)
	require.NoError(t, err)

	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID:                "w3c-session",
		State:                    state,
		Nonce:                    "w3c-nonce",
		ClientID:                 "x509_san_dns:verifier.example.com",
		Scopes:                   []string{scope},
		EphemeralEncryptionKeyID: kid,
	}))

	body, err := json.Marshal(openid4vp.VPResponse{
		State:   state,
		VPToken: map[string][]string{scope: {string(created.CredentialJSON)}},
	})
	require.NoError(t, err)
	encrypted, err := jwe.Encrypt(body,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	resp, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
		Response: string(encrypted),
	})
	require.NoError(t, err, "a signed W3C credential must verify like any other format")
	require.NotNil(t, resp)

	// The claims have to reach the cache, not merely pass verification.
	// The response code is the last path/query element of the callback URL.
	u, err := url.Parse(resp.RedirectURI)
	require.NoError(t, err)
	responseCode := u.Query().Get("response_code")
	require.NotEmpty(t, responseCode, "the callback names the cached credential")

	cached, ok := client.cacheService.Credential.Get(ctx, responseCode)
	require.True(t, ok, "the verified credential is cached for the callback")
	require.Len(t, cached, 1)
	assert.Equal(t, scope, cached[0].Scope)

	subject, ok := cached[0].Credential["credentialSubject"].(map[string]any)
	require.True(t, ok, "the whole credential map is cached, so validations can address credentialSubject.*")
	assert.Equal(t, "Master of Science", subject["degree"])
}
