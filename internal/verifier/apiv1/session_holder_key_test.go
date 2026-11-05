package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// denyingEvaluator answers for the issuer's verification method and refuses
// every other one the way a PDP does, recording what it was asked. A holder's
// did:key is nobody's registry entry, so a deployment's PDP answers for it
// exactly like this.
type denyingEvaluator struct {
	issuerVM  string
	issuerKey crypto.PublicKey
	asked     []string
}

func (e *denyingEvaluator) Evaluate(context.Context, *trust.EvaluationRequest) (*trust.TrustDecision, error) {
	return &trust.TrustDecision{Trusted: true}, nil
}

func (e *denyingEvaluator) SupportsKeyType(trust.KeyType) bool { return true }

func (e *denyingEvaluator) ResolveKey(_ context.Context, verificationMethod string) (crypto.PublicKey, error) {
	e.asked = append(e.asked, verificationMethod)
	if verificationMethod == e.issuerVM {
		return e.issuerKey, nil
	}
	return nil, fmt.Errorf("resolution denied for %s: no registry returned positive match", verificationMethod)
}

// TestVerificationDirectPostResolvesAHolderDidKeyLocally drives a did:key-signed
// presentation through the SESSION path - POST /verification/direct_post, the
// endpoint the verifier's own UI preset posts to - with a PDP that answers for
// the issuer and denies everything else.
//
// The OIDC path has resolved a holder's did:key from the identifier since the
// resolver was added; this path built its handler without one, so the holder's
// verification method went to the trust service and came back
// "resolution denied ... no registry returned positive match". Every
// presentation from a did:key wallet failed with 500, which is what the
// Accredify wallet hit on the button flow while the same wallet passed over
// OIDC.
func TestVerificationDirectPostResolvesAHolderDidKeyLocally(t *testing.T) {
	ctx := t.Context()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const degreeContext = "https://example.org/degree"
	credential.GetGlobalLoader().AddContext(degreeContext,
		`{"@context":{"UniversityDegreeCredential":"https://example.org/degree#UniversityDegreeCredential"}}`)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderDID := didKeyP256(t, &holderKey.PublicKey)
	holderVM := holderDID + "#" + holderDID[len("did:key:"):]

	issuerHandler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20SignerConfig(&openid4vp.VC20SignerConfig{
			PrivateKey:         issuerKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		}),
	)
	require.NoError(t, err)

	// The holder is the credential's subject: a presentation's signer has to
	// be one, so the did:key appears in both places, as it does in the wild.
	created, err := issuerHandler.CreateCredential(ctx, &openid4vp.VC20CreateRequest{
		Types:              []string{"UniversityDegreeCredential"},
		AdditionalContexts: []string{degreeContext},
		Subject:            map[string]any{"id": holderDID, "degree": "Master of Science"},
	})
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	evaluator := &denyingEvaluator{
		issuerVM:  "did:example:issuer#key-1",
		issuerKey: &issuerKey.PublicKey,
	}
	client.trustEvaluator = evaluator

	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
	require.NoError(t, err)
	client.openid4vp = openid4vpClient

	notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	require.NoError(t, err)
	client.notify = notifyService

	const (
		kid   = "holder-did-key-kid"
		state = "holder-did-key-state"
		scope = "diploma"
		nonce = "holder-did-key-nonce"
		audi  = "x509_san_dns:verifier.example.com"
	)
	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
	require.NoError(t, err)

	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID:                "holder-did-key-session",
		WalletFollowsRedirect:    true,
		State:                    state,
		Nonce:                    nonce,
		ClientID:                 audi,
		Scopes:                   []string{scope},
		EphemeralEncryptionKeyID: kid,
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     scope,
			Format: openid4vp.FormatLdpVCDCQL,
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{{
				openid4vp.BaseVCTypeIRI,
				"https://example.org/degree#UniversityDegreeCredential",
			}}},
		}}},
	}))

	vp, err := openid4vp.NewVPBuilder().BuildVC20Presentation(
		[][]byte{created.CredentialJSON},
		holderKey,
		&openid4vp.VPBuildOptions{
			HolderDID:          holderDID,
			VerificationMethod: holderVM,
			Nonce:              nonce,
			Domain:             audi,
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

	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
		Response: string(encrypted),
	})
	require.NoError(t, err, "a did:key holder must verify on the session path too")

	// The property, not only the outcome: the holder's key never went to the
	// trust service. A resolver that happened to answer would hide the bug.
	assert.NotContains(t, evaluator.asked, holderVM,
		"the holder's did:key is read from the identifier, never put to the PDP")
	assert.Contains(t, evaluator.asked, evaluator.issuerVM,
		"the issuer's key still comes from the trust service")
}

// TestVerificationDirectPostStillTrustsADidKeyIssuer: resolving the holder
// locally relaxes nothing about the issuer, and the method the issuer happens
// to use does not decide that. Here the ISSUER is a did:key too - its key is
// as readable from its identifier as the holder's - and a PDP that denies it
// must still refuse the presentation. Reading the issuer's key out of its
// identifier would turn "this is signed" into "this is trusted", which is the
// whole of what the trust service is for.
func TestVerificationDirectPostStillTrustsADidKeyIssuer(t *testing.T) {
	ctx := t.Context()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const degreeContext = "https://example.org/degree"
	credential.GetGlobalLoader().AddContext(degreeContext,
		`{"@context":{"UniversityDegreeCredential":"https://example.org/degree#UniversityDegreeCredential"}}`)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderDID := didKeyP256(t, &holderKey.PublicKey)

	// The issuer is a did:key as well, so its key is just as readable from
	// its identifier as the holder's. Whether it may issue is still the
	// trust service's answer, and this PDP says no.
	issuerDID := didKeyP256(t, &issuerKey.PublicKey)
	issuerHandler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20SignerConfig(&openid4vp.VC20SignerConfig{
			PrivateKey:         issuerKey,
			IssuerID:           issuerDID,
			VerificationMethod: issuerDID + "#" + issuerDID[len("did:key:"):],
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		}),
	)
	require.NoError(t, err)

	created, err := issuerHandler.CreateCredential(ctx, &openid4vp.VC20CreateRequest{
		Types:              []string{"UniversityDegreeCredential"},
		AdditionalContexts: []string{degreeContext},
		Subject:            map[string]any{"id": holderDID, "degree": "Master of Science"},
	})
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	// issuerVM is empty, so nothing resolves: the PDP denies every method.
	client.trustEvaluator = &denyingEvaluator{}

	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
	require.NoError(t, err)
	client.openid4vp = openid4vpClient

	notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	require.NoError(t, err)
	client.notify = notifyService

	const (
		kid   = "denied-issuer-kid"
		state = "denied-issuer-state"
		scope = "diploma"
		nonce = "denied-issuer-nonce"
		audi  = "x509_san_dns:verifier.example.com"
	)
	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
	require.NoError(t, err)

	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID:                "denied-issuer-session",
		WalletFollowsRedirect:    true,
		State:                    state,
		Nonce:                    nonce,
		ClientID:                 audi,
		Scopes:                   []string{scope},
		EphemeralEncryptionKeyID: kid,
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     scope,
			Format: openid4vp.FormatLdpVCDCQL,
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{{
				openid4vp.BaseVCTypeIRI,
				"https://example.org/degree#UniversityDegreeCredential",
			}}},
		}}},
	}))

	vp, err := openid4vp.NewVPBuilder().BuildVC20Presentation(
		[][]byte{created.CredentialJSON},
		holderKey,
		&openid4vp.VPBuildOptions{
			HolderDID:          holderDID,
			VerificationMethod: holderDID + "#" + holderDID[len("did:key:"):],
			Nonce:              nonce,
			Domain:             audi,
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

	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
		Response: string(encrypted),
	})
	require.Error(t, err, "a did:key issuer the PDP denies must not pass because its key is readable")
	assert.Contains(t, err.Error(), "resolution denied",
		"the issuer's key is refused by the trust service, not read from the identifier")
}

// didKeyP256 is the did:key of a P-256 public key: multicodec 0x1200
// (p256-pub), varint-encoded 0x80 0x24, followed by the compressed point,
// base58btc. The key IS the identifier, which is why no registry has to list
// a holder and why the signature alone settles the holder's question.
func didKeyP256(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	multikey, err := multibase.Encode(multibase.Base58BTC, append([]byte{0x80, 0x24}, compressed...))
	require.NoError(t, err)
	return "did:key:" + multikey
}
