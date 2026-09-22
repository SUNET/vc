package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticKeyEvaluator is a trust evaluator that can also resolve one
// verification method, which is what W3C Data Integrity needs and what
// AllowAllEvaluator deliberately cannot do without a PDP.
type staticKeyEvaluator struct {
	keys map[string]crypto.PublicKey
}

func (e *staticKeyEvaluator) Evaluate(context.Context, *trust.EvaluationRequest) (*trust.TrustDecision, error) {
	return &trust.TrustDecision{Trusted: true}, nil
}
func (e *staticKeyEvaluator) SupportsKeyType(trust.KeyType) bool { return true }
func (e *staticKeyEvaluator) ResolveKey(_ context.Context, verificationMethod string) (crypto.PublicKey, error) {
	key, ok := e.keys[verificationMethod]
	if !ok {
		return nil, fmt.Errorf("no key for %q", verificationMethod)
	}
	return key, nil
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

	// A context defining the custom term, registered locally so expansion is
	// offline and deterministic. In a deployment this is a published URL,
	// configured as credential_contexts and fetched by the verifier.
	const degreeContext = "https://example.org/degree"
	credential.GetGlobalLoader().AddContext(degreeContext,
		`{"@context":{"UniversityDegreeCredential":"https://example.org/degree#UniversityDegreeCredential"}}`)

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
		Types:              []string{"UniversityDegreeCredential"},
		AdditionalContexts: []string{degreeContext},
		Subject:            map[string]any{"id": "did:example:subject", "degree": "Master of Science"},
	})
	require.NoError(t, err)

	// The holder signs the presentation; the issuer signed the credential.
	// Two distinct keys, which is the whole point of holder binding.
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = &staticKeyEvaluator{keys: map[string]crypto.PublicKey{
		"did:example:issuer#key-1": &issuerKey.PublicKey,
		"did:example:holder#key-1": &holderKey.PublicKey,
	}}

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

	// The query the request was built from. require_cryptographic_holder_binding
	// is explicitly false: this credential carries only the issuer's proof, and
	// the verifier refuses to pretend an unbound credential satisfies a request
	// that asked for binding.
	requestedTypes := [][]string{{openid4vp.BaseVCTypeIRI, "https://example.org/degree#UniversityDegreeCredential"}}
	var requestedMeta openid4vp.MetaQuery
	saveSession := func(t *testing.T, holderBinding *bool) {
		t.Helper()
		require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
			SessionID:                "w3c-session",
			State:                    state,
			Nonce:                    "w3c-nonce",
			ClientID:                 "x509_san_dns:verifier.example.com",
			Scopes:                   []string{scope},
			EphemeralEncryptionKeyID: kid,
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
				ID:                                scope,
				Format:                            openid4vp.FormatLdpVCDCQL,
				Meta:                              metaFor(requestedTypes, requestedMeta),
				RequireCryptographicHolderBinding: holderBinding,
			}}},
		}))
	}
	saveSession(t, nil) // nil is the spec default: holder binding required

	// A real presentation: the holder signs the VP with proofPurpose
	// "authentication", carrying this session's nonce as the challenge and
	// naming this verifier as the domain.
	vp, err := openid4vp.NewVPBuilder().BuildVC20Presentation(
		[][]byte{created.CredentialJSON},
		holderKey,
		&openid4vp.VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "w3c-nonce",
			Domain:             "x509_san_dns:verifier.example.com",
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		},
	)
	require.NoError(t, err)

	body, err := json.Marshal(openid4vp.VPResponse{
		State:   state,
		VPToken: map[string][]string{scope: {string(vp)}},
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

	// A BARE credential - issuer-signed, no presentation proof - proves it was
	// issued, not that this holder is presenting it now. Accepting one where
	// binding was required is exactly the replay this guards against.
	bareBody, err := json.Marshal(openid4vp.VPResponse{
		State:   state,
		VPToken: map[string][]string{scope: {string(created.CredentialJSON)}},
	})
	require.NoError(t, err)
	bare, err := jwe.Encrypt(bareBody,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	saveSession(t, nil)
	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(bare)})
	require.Error(t, err, "a bare credential must not satisfy a request requiring holder binding")
	assert.Contains(t, err.Error(), "presentation")

	// A presentation bound to a DIFFERENT session. It verifies cryptographically
	// - the holder really signed it - and must still be refused, because the
	// challenge names someone else's exchange. This is replay.
	replayed, err := openid4vp.NewVPBuilder().BuildVC20Presentation(
		[][]byte{created.CredentialJSON},
		holderKey,
		&openid4vp.VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "a-different-sessions-nonce",
			Domain:             "x509_san_dns:verifier.example.com",
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		},
	)
	require.NoError(t, err)
	replayBody, err := json.Marshal(openid4vp.VPResponse{
		State:   state,
		VPToken: map[string][]string{scope: {string(replayed)}},
	})
	require.NoError(t, err)
	replayEnc, err := jwe.Encrypt(replayBody,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	saveSession(t, nil)
	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(replayEnc)})
	require.Error(t, err, "a presentation bound to another session must be refused")
	assert.Contains(t, err.Error(), "challenge")

	// A credential that verifies perfectly but is not the type the request
	// asked for. meta.type_values is the constraint; if it is not enforced on
	// the response, the wallet chooses which credential answers the scope.
	requestedTypes = [][]string{{openid4vp.BaseVCTypeIRI, "https://example.org/degree#DoctoralDegreeCredential"}}
	saveSession(t, nil)
	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(encrypted)})
	require.Error(t, err, "a credential of the wrong type must not answer the scope")
	assert.Contains(t, err.Error(), "requested types")

	// A W3C query carrying no type_values constrains no types. Template-built
	// queries never pass through ValidateCredentialQuery, so one can arrive
	// like this - here with a vct_values meta that is meaningless for a W3C
	// format - and accepting it would let the wallet pick any W3C credential.
	requestedTypes = nil
	requestedMeta = openid4vp.MetaQuery{VCTValues: []string{"urn:not:a:w3c:constraint"}}
	saveSession(t, nil)
	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(encrypted)})
	require.Error(t, err, "an unconstrained W3C query must not accept whatever arrives")
	assert.Contains(t, err.Error(), "cannot constrain a credential")

	// The alternatives that have length but still match everything. A length
	// check would let all of these through; the query validator is what knows
	// they do not narrow, which is why the recovered query goes through it.
	for _, unconstraining := range [][][]string{
		{{}},                        // an empty alternative
		{{openid4vp.BaseVCTypeIRI}}, // every W3C credential carries this
		{{openid4vp.BaseVCTypeIRI, "https://example.org/degree#UniversityDegreeCredential"}, {openid4vp.BaseVCTypeIRI}},
	} {
		requestedTypes = unconstraining
		saveSession(t, nil)
		_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(encrypted)})
		require.Error(t, err, "%v does not narrow and must be refused", unconstraining)
		assert.Contains(t, err.Error(), "cannot constrain a credential")
	}
}

// metaFor builds the request's meta: the type constraint when there is one,
// otherwise whatever the caller wants to stand in for a mis-built query.
func metaFor(typeValues [][]string, fallback openid4vp.MetaQuery) openid4vp.MetaQuery {
	if len(typeValues) > 0 {
		return openid4vp.MetaQuery{TypeValues: typeValues}
	}
	return fallback
}
