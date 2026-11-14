package openid4vp

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompactTypeNames(t *testing.T) {
	for name, tc := range map[string]struct {
		in   any
		want []string
	}{
		"a single string":         {"VerifiablePresentation", []string{"VerifiablePresentation"}},
		"an array":                {[]any{"VerifiableCredential", "IndividualIDCredential"}, []string{"VerifiableCredential", "IndividualIDCredential"}},
		"non-strings are ignored": {[]any{"A", 1, nil, "B"}, []string{"A", "B"}},
		"a number":                {1.0, nil},
		"an object":               {map[string]any{"a": "b"}, nil},
		"absent":                  {nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, compactTypeNames(tc.in))
		})
	}
}

// TestPresentationTypeAsString: a presentation with a single type may spell it
// as a string. It must still be taken for a presentation, so that the holder's
// proof is demanded; read as a bare credential it is refused outright. The
// document has no proof, so the failure is the binding one, not "bare".
func TestPresentationTypeAsString(t *testing.T) {
	h := mustHandler(t, WithVC20StaticKey(nil), WithVC20PresentationBinding("nonce", "verifier"))
	for name, typ := range map[string]string{
		"string": `"VerifiablePresentation"`,
		"array":  `["VerifiablePresentation"]`,
	} {
		t.Run(name, func(t *testing.T) {
			vp := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":` + typ + `,
				"holder":"did:key:z6Mk","verifiableCredential":{"type":["VerifiableCredential"]}}`
			_, err := h.VerifyAndExtract(t.Context(), vp)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "bare credential")
			assert.Contains(t, err.Error(), "presentation is not bound to this session")
		})
	}

	t.Run("a credential is still refused as bare", func(t *testing.T) {
		vc := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":"VerifiableCredential","credentialSubject":{"a":"b"}}`
		_, err := h.VerifyAndExtract(t.Context(), vc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bare credential")
	})
}

type denyingResolver struct{}

func (denyingResolver) ResolveKey(context.Context, string) (crypto.PublicKey, error) {
	return nil, errors.New("resolution denied: no registry returned positive match")
}

type fixedResolver struct{ key crypto.PublicKey }

func (r fixedResolver) ResolveKey(context.Context, string) (crypto.PublicKey, error) {
	return r.key, nil
}

// TestHolderKeyResolverIsSeparate: the key of a presentation's own proof comes
// from the holder resolver when one is set, and the issuer's resolver is not
// asked. With only the (denying) trust-backed resolver, a holder's did:key is
// refused at key resolution; with a holder resolver the check goes on to the
// signature, which this unsigned document then fails - a later step.
func TestHolderKeyResolverIsSeparate(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vp := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":"VerifiablePresentation",
		"holder":"did:key:z6Mk","verifiableCredential":{"type":["VerifiableCredential"]},
		"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-rdfc-2022","proofPurpose":"authentication",
		  "challenge":"nonce","domain":"verifier","verificationMethod":"did:key:z6Mk#z6Mk","proofValue":"zabc"}}`

	t.Run("one resolver for both: the holder key is refused", func(t *testing.T) {
		h := mustHandler(t, WithVC20KeyResolver(denyingResolver{}), WithVC20PresentationBinding("nonce", "verifier"))
		_, err := h.VerifyAndExtract(t.Context(), vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving holder key")
	})

	t.Run("a holder resolver is used for the holder proof", func(t *testing.T) {
		h := mustHandler(t, WithVC20KeyResolver(denyingResolver{}), WithVC20HolderKeyResolver(fixedResolver{pub}),
			WithVC20PresentationBinding("nonce", "verifier"))
		_, err := h.VerifyAndExtract(t.Context(), vp)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "resolving holder key")
		assert.NotContains(t, err.Error(), "resolution denied")
	})
}
