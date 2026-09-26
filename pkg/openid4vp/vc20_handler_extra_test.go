package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpandedTypesIgnoresDecoyNodes pins type isolation against the realistic
// attack: a wallet sends expanded JSON-LD carrying a decoy node beside the
// credential, hoping its type satisfies the constraint.
//
// The test proves the hazard and the protection in one pass, so it cannot go
// vacuous: expanding the WHOLE document really does pick up the decoy, while
// the path the handler actually takes - extractCredentialFromExpanded, then
// expandedTypes on that node alone - does not.
func TestExpandedTypesIgnoresDecoyNodes(t *testing.T) {
	const decoy = "https://example.org/degree#UniversityDegreeCredential"
	const vcIRI = "https://www.w3.org/2018/credentials#VerifiableCredential"

	expanded := []any{
		map[string]any{
			"@type": []any{vcIRI},
			"https://www.w3.org/2018/credentials#credentialSubject": []any{
				map[string]any{"@id": "did:example:subject"},
			},
		},
		map[string]any{"@type": []any{decoy}},
	}

	h, err := NewVC20Handler()
	require.NoError(t, err)

	// credBytes is the WHOLE document, as the handler keeps it for signature
	// verification; credMap is the credential node it identified. buildResult
	// gets both, and which one it reads for types is the whole question -
	// reading the document picks up the decoy.
	credBytes, err := json.Marshal(expanded)
	require.NoError(t, err)
	credMap, err := h.extractCredentialFromExpanded(expanded)
	require.NoError(t, err)

	result, err := h.buildResult(credBytes, credMap, map[string]any{}, false)
	require.NoError(t, err)
	assert.Contains(t, result.TypeIRIs, vcIRI, "the credential's own type is read")
	assert.NotContains(t, result.TypeIRIs, decoy, "a sibling node's type is not the credential's")

}

// TestExpandedTypesDropsRelativeIRIs pins the other half: a term no context
// defines expands to itself, which identifies nothing and must never satisfy a
// constraint.
func TestExpandedTypesDropsRelativeIRIs(t *testing.T) {
	var credNode map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{
		"@context":["https://www.w3.org/ns/credentials/v2"],
		"type":["VerifiableCredential","UniversityDegreeCredential"],
		"issuer":"did:example:issuer",
		"credentialSubject":{"degree":"MSc"}}`), &credNode))

	iris, err := expandedTypes(credNode)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://www.w3.org/2018/credentials#VerifiableCredential"}, iris,
		"the undefined term expands to a relative IRI and is dropped")
}

// TestExpandedPresentationRefusedWhenBindingRequired: extractCredentialFromExpanded
// discards the presentation wrapper and its proof, so the binding cannot be
// checked afterwards. Refuse plainly rather than report a presentation as a
// bare credential.
func TestExpandedPresentationRefused(t *testing.T) {
	// Both postures: the credential bytes cannot be isolated from the wrapper
	// either way, so binding is not what decides this.
	for name, h := range map[string]*VC20Handler{
		"holder binding required":  mustHandler(t, WithVC20StaticKey(nil), WithVC20PresentationBinding("nonce", "verifier")),
		"holder binding opted out": mustHandler(t, WithVC20StaticKey(nil)),
	} {
		t.Run(name, func(t *testing.T) {
			expandedVP := `[{"@type":["https://www.w3.org/2018/credentials#VerifiablePresentation"],
			  "https://www.w3.org/2018/credentials#verifiableCredential":[{"@type":["https://www.w3.org/2018/credentials#VerifiableCredential"]}]}]`
			_, err := h.VerifyAndExtract(t.Context(), expandedVP)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "expanded-form presentations")
		})
	}
}

func mustHandler(t *testing.T, opts ...VC20HandlerOption) *VC20Handler {
	t.Helper()
	h, err := NewVC20Handler(opts...)
	require.NoError(t, err)
	return h
}

// rotatingResolver answers with a different key each call, which is what a
// remote or rotating key resolver can do.
type rotatingResolver struct {
	keys  []crypto.PublicKey
	calls int
}

func (r *rotatingResolver) ResolveKey(context.Context, string) (crypto.PublicKey, error) {
	if r.calls >= len(r.keys) {
		return nil, errors.New("exhausted")
	}
	k := r.keys[r.calls]
	r.calls++
	return k, nil
}

// TestVerifyAndExtractReturnsTheVerifyingKey pins what a caller must evaluate
// trust on.
//
// Resolving the verification method a second time can answer differently, and
// then the key judged is not the key that signed. The result carries the key
// the signature was actually verified with so the caller need not re-resolve.
func TestVerifyAndExtractReturnsTheVerifyingKey(t *testing.T) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         signing,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteECDSA2019,
		}),
	)
	require.NoError(t, err)
	created, err := issuer.CreateCredential(t.Context(), &VC20CreateRequest{
		Types:   []string{"VerifiableCredential"},
		Subject: map[string]any{"id": "did:example:subject"},
	})
	require.NoError(t, err)

	// First call returns the real key (verification succeeds); a second would
	// return a different one.
	resolver := &rotatingResolver{keys: []crypto.PublicKey{&signing.PublicKey, &other.PublicKey}}
	h, err := NewVC20Handler(WithVC20KeyResolver(resolver))
	require.NoError(t, err)

	result, err := h.VerifyAndExtract(t.Context(), string(created.CredentialJSON))
	require.NoError(t, err)

	assert.Equal(t, &signing.PublicKey, result.IssuerKey,
		"the key returned is the one the signature verified with")
	assert.NotEqual(t, &other.PublicKey, result.IssuerKey,
		"a caller re-resolving would have got this one instead")
	assert.Equal(t, 1, resolver.calls, "and it resolved once, not twice")
}
