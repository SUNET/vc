package openid4vp

import (
	"context"
	"crypto"
	"errors"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/SUNET/vc/pkg/vc20/credential"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDidOf(t *testing.T) {
	assert.Equal(t, "did:key:z6Mk", didOf("did:key:z6Mk#z6Mk"))
	assert.Equal(t, "did:key:z6Mk", didOf("did:key:z6Mk"))
	assert.Equal(t, "", didOf(""))
}

func TestCheckSubjectBinding(t *testing.T) {
	const signer = "did:key:z6MkAlice"
	for name, tc := range map[string]struct {
		cred    string
		wantErr string
	}{
		"the signer is the subject":             {`{"credentialSubject":{"id":"did:key:z6MkAlice","a":1}}`, ""},
		"the subject id carries a fragment":     {`{"credentialSubject":{"id":"did:key:z6MkAlice#z6MkAlice"}}`, ""},
		"the signer is one of several subjects": {`{"credentialSubject":[{"id":"did:key:z6MkBob"},{"id":"did:key:z6MkAlice"}]}`, ""},
		"another subject":                       {`{"credentialSubject":{"id":"did:key:z6MkBob"}}`, "not a subject of the credential"},
		"no subject id":                         {`{"credentialSubject":{"a":1}}`, "names no subject"},
		"no credentialSubject":                  {`{}`, "names no subject"},
		"a subject that is not an object":       {`{"credentialSubject":"did:key:z6MkAlice"}`, "names no subject"},
		"a non-string id":                       {`{"credentialSubject":{"id":7}}`, "names no subject"},
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(tc.cred), &m))
			err := checkSubjectBinding(m, signer)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestPresentationProofReturnsTheSigner: what comes back is the identifier the
// signature was verified under, and a presentation that names a different
// holder than its signer is refused, not trusted for the member it wrote.
func TestPresentationProofReturnsTheSigner(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const signer = "did:key:z6MkAlice"

	build := func(holder string) ([]byte, map[string]any) {
		vp, err := NewVPBuilder().BuildVC20Presentation(
			[][]byte{signedTestCredential(t, issuerKey)}, holderKey,
			&VPBuildOptions{
				HolderDID: holder, VerificationMethod: signer + "#key-1",
				Nonce: "nonce", Domain: "verifier", Cryptosuite: CryptosuiteECDSA2019, Created: time.Now().UTC(),
			})
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(vp, &m))
		return vp, m
	}
	h := &VC20Handler{
		keyResolver:          denyingResolver{},
		holderKeyResolver:    fixedResolver{&holderKey.PublicKey},
		requireHolderBinding: true,
		expectedChallenge:    "nonce",
		expectedDomain:       "verifier",
	}

	t.Run("signed by the holder it names", func(t *testing.T) {
		vp, m := build(signer)
		got, err := h.verifyPresentationProof(t.Context(), vp, m)
		require.NoError(t, err)
		assert.Equal(t, signer, got)
	})

	t.Run("names another holder than the signer", func(t *testing.T) {
		vp, m := build("did:key:z6MkBob")
		_, err := h.verifyPresentationProof(t.Context(), vp, m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "names holder")
	})
}

type mapResolver map[string]crypto.PublicKey

func (m mapResolver) ResolveKey(_ context.Context, vm string) (crypto.PublicKey, error) {
	if k, ok := m[vm]; ok {
		return k, nil
	}
	return nil, errors.New("resolution denied")
}

// TestPresentationMustBeSignedBySubject: end to end through VerifyAndExtract. A
// genuine credential, a trusted issuer, a fresh presentation with the right
// challenge and domain: it verifies when the signer is the credential's
// subject, and is refused when it is anyone else, who holds only a copy.
func TestPresentationMustBeSignedBySubject(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const signer = "did:key:z6MkAlice"

	const degreeContext = "https://example.org/degree"
	credential.GetGlobalLoader().AddContext(degreeContext,
		`{"@context":{"UniversityDegreeCredential":"https://example.org/degree#UniversityDegreeCredential"}}`)
	issuer, err := NewVC20Handler(WithVC20SignerConfig(&VC20SignerConfig{
		PrivateKey: issuerKey, IssuerID: "did:example:issuer",
		VerificationMethod: "did:example:issuer#key-1", Cryptosuite: CryptosuiteECDSA2019,
	}))
	require.NoError(t, err)
	credFor := func(subject string) []byte {
		created, err := issuer.CreateCredential(t.Context(), &VC20CreateRequest{
			Types: []string{"UniversityDegreeCredential"}, AdditionalContexts: []string{degreeContext},
			Subject: map[string]any{"id": subject, "degree": "MSc"},
		})
		require.NoError(t, err)
		return created.CredentialJSON
	}
	present := func(subject string) []byte {
		vp, err := NewVPBuilder().BuildVC20Presentation([][]byte{credFor(subject)}, holderKey, &VPBuildOptions{
			HolderDID: signer, VerificationMethod: signer + "#key-1",
			Nonce: "nonce", Domain: "verifier", Cryptosuite: CryptosuiteECDSA2019, Created: time.Now().UTC(),
		})
		require.NoError(t, err)
		return vp
	}
	h := mustHandler(t,
		WithVC20KeyResolver(mapResolver{"did:example:issuer#key-1": &issuerKey.PublicKey}),
		WithVC20HolderKeyResolver(mapResolver{signer + "#key-1": &holderKey.PublicKey}),
		WithVC20PresentationBinding("nonce", "verifier"))

	t.Run("the signer is the subject", func(t *testing.T) {
		res, err := h.VerifyAndExtract(t.Context(), string(present(signer)))
		require.NoError(t, err)
		assert.Equal(t, signer, res.Holder)
		assert.True(t, res.HolderBound)
	})

	t.Run("someone else holding a copy", func(t *testing.T) {
		_, err := h.VerifyAndExtract(t.Context(), string(present("did:key:z6MkBob")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a subject of the credential")
	})
}
