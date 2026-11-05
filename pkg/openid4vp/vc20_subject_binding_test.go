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
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

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
		"the subject id is the signing key":     {`{"credentialSubject":{"id":"did:key:z6MkAlice#z6MkAlice"}}`, ""},
		"the signer is one of several subjects": {`{"credentialSubject":[{"id":"did:key:z6MkBob"},{"id":"did:key:z6MkAlice"}]}`, ""},
		"another subject":                       {`{"credentialSubject":{"id":"did:key:z6MkBob"}}`, "not a subject of the credential"},
		// Holding a key of a DID document is not being every resource described in it:
		// the fragment is what tells #alice from #bob, and it is not dropped. The local
		// resolver reads a did:key out of the identifier whatever fragment follows, so
		// this is a fragment a presenter can sign under at will - which is why what
		// counts is derived from the DID rather than from the proof.
		"another resource of the signer's DID": {`{"credentialSubject":{"id":"did:key:z6MkAlice#alice"}}`, "not a subject of the credential"},
		"no subject id":                        {`{"credentialSubject":{"a":1}}`, "names no subject"},
		"no credentialSubject":                 {`{}`, "names no subject"},
		"a subject that is not an object":      {`{"credentialSubject":"did:key:z6MkAlice"}`, "names no subject"},
		"a non-string id":                      {`{"credentialSubject":{"id":7}}`, "names no subject"},
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

// bindingFixture is the end-to-end setup both tests below share: a genuine credential
// from a trusted issuer, wrapped in a fresh presentation with the right challenge and
// domain, signed by one holder key. What differs between them is the credential's
// subject, which is the whole question.
type bindingFixture struct {
	holderKey, issuerKey *ecdsa.PrivateKey
	issuer               *VC20Handler
	signer               string
}

func newBindingFixture(t *testing.T, context, credType string) *bindingFixture {
	t.Helper()
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credential.GetGlobalLoader().AddContext(context,
		`{"@context":{"`+credType+`":"`+context+`#`+credType+`","fullName":"https://schema.org/name"}}`)
	issuer, err := NewVC20Handler(WithVC20SignerConfig(&VC20SignerConfig{
		PrivateKey: issuerKey, IssuerID: "did:example:issuer",
		VerificationMethod: "did:example:issuer#key-1", Cryptosuite: CryptosuiteECDSA2019,
	}))
	require.NoError(t, err)
	return &bindingFixture{holderKey: holderKey, issuerKey: issuerKey, issuer: issuer, signer: "did:key:z6MkAlice"}
}

// credential issues one credential with the given subject; context and type come from the
// fixture's own, registered in newBindingFixture.
func (f *bindingFixture) credential(t *testing.T, context, credType string, subject map[string]any) []byte {
	t.Helper()
	created, err := f.issuer.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{credType}, AdditionalContexts: []string{context}, Subject: subject,
	})
	require.NoError(t, err)
	return created.CredentialJSON
}

// present wraps credentials in a presentation signed by the fixture's holder key, under
// a verification method of the presenter's choosing - which is what it is, in a proof.
func (f *bindingFixture) present(t *testing.T, credJSON []byte, verificationMethod string) []byte {
	t.Helper()
	vp, err := NewVPBuilder().BuildVC20Presentation([][]byte{credJSON}, f.holderKey, &VPBuildOptions{
		HolderDID: f.signer, VerificationMethod: verificationMethod,
		Nonce: "nonce", Domain: "verifier", Cryptosuite: CryptosuiteECDSA2019, Created: time.Now().UTC(),
	})
	require.NoError(t, err)
	return vp
}

// resolvers resolve the issuer's key, and the holder's under any fragment of the
// holder's DID - which is what the local resolver does for did:key and did:jwk: it reads
// the key out of the identifier and never looks at the fragment.
func (f *bindingFixture) resolvers() []VC20HandlerOption {
	return []VC20HandlerOption{
		WithVC20KeyResolver(mapResolver{"did:example:issuer#key-1": &f.issuerKey.PublicKey}),
		WithVC20HolderKeyResolver(anyFragmentResolver{did: f.signer, key: &f.holderKey.PublicKey}),
	}
}

// anyFragmentResolver mirrors pkg/keyresolver's local resolver: a did:key or did:jwk
// carries its key in the identifier, so whatever fragment follows is ignored.
type anyFragmentResolver struct {
	did string
	key crypto.PublicKey
}

func (r anyFragmentResolver) ResolveKey(_ context.Context, vm string) (crypto.PublicKey, error) {
	if didOf(vm) == r.did {
		return r.key, nil
	}
	return nil, errors.New("resolution denied")
}

// TestPresentationMustBeSignedBySubject: end to end through VerifyAndExtract. A
// genuine credential, a trusted issuer, a fresh presentation with the right
// challenge and domain: it verifies when the signer is the credential's
// subject, and is refused when it is anyone else, who holds only a copy.
func TestPresentationMustBeSignedBySubject(t *testing.T) {
	const ctx, credType = "https://example.org/degree", "UniversityDegreeCredential"
	f := newBindingFixture(t, ctx, credType)
	present := func(subject string) []byte {
		return f.present(t, f.credential(t, ctx, credType, map[string]any{"id": subject, "fullName": "Alice Example"}), f.signer+"#"+"z6MkAlice")
	}
	h := mustHandler(t, append(f.resolvers(), WithVC20PresentationBinding("nonce", "verifier"))...)

	t.Run("the signer is the subject", func(t *testing.T) {
		res, err := h.VerifyAndExtract(t.Context(), string(present(f.signer)))
		require.NoError(t, err)
		assert.Equal(t, f.signer, res.Holder)
		assert.True(t, res.HolderBound)
	})

	t.Run("someone else holding a copy", func(t *testing.T) {
		_, err := h.VerifyAndExtract(t.Context(), string(present("did:key:z6MkBob")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a subject of the credential")
	})
}

// TestPresentationOfACredentialWithNoSubjectID: the shape an Accredify wallet sends -
// a credential whose credentialSubject carries claims but no id (see the fixture in
// vp_token_object_test.go). There is nothing in it to bind a presenter to, so a query
// that requires cryptographic holder binding refuses it, and one that does not accepts
// it. The refusal is the policy, not an accident of this change: a credential naming no
// subject is a bearer credential, and anyone holding a copy could present it.
func TestPresentationOfACredentialWithNoSubjectID(t *testing.T) {
	const ctx, credType = "https://example.org/individual-id", "IndividualIDCredential"
	f := newBindingFixture(t, ctx, credType)
	cred := f.credential(t, ctx, credType, map[string]any{"fullName": "Alice Example"})

	t.Run("refused where binding is required", func(t *testing.T) {
		h := mustHandler(t, append(f.resolvers(), WithVC20PresentationBinding("nonce", "verifier"))...)
		_, err := h.VerifyAndExtract(t.Context(), string(f.present(t, cred, f.signer+"#z6MkAlice")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "names no subject")
	})

	t.Run("accepted where the query does not require binding", func(t *testing.T) {
		h := mustHandler(t, f.resolvers()...)
		res, err := h.VerifyAndExtract(t.Context(), string(cred))
		require.NoError(t, err)
		assert.False(t, res.HolderBound)
	})
}

// TestPresentationCannotInventTheSubjectItIsBoundTo: the verification method in a proof
// is the presenter's to write, and the local resolver reads a did:key out of the
// identifier whatever fragment follows it. So a holder can sign with their own key under
// did:key:<theirs>#bob. That must not make them the subject "did:key:<theirs>#bob" the
// issuer named - what signing as a DID shows control of is derived from the DID, not
// from the proof.
func TestPresentationCannotInventTheSubjectItIsBoundTo(t *testing.T) {
	const ctx, credType = "https://example.org/invented", "InventedCredential"
	f := newBindingFixture(t, ctx, credType)
	h := mustHandler(t, append(f.resolvers(), WithVC20PresentationBinding("nonce", "verifier"))...)

	for name, tc := range map[string]struct {
		subject, verificationMethod string
		wantErr                     string
	}{
		"a fragment the presenter chose": {
			subject: f.signer + "#bob", verificationMethod: f.signer + "#bob",
			wantErr: "not a subject of the credential",
		},
		"the did:key verification method": {
			subject: f.signer + "#z6MkAlice", verificationMethod: f.signer + "#z6MkAlice",
		},
		"the DID itself, signed under some other fragment": {
			subject: f.signer, verificationMethod: f.signer + "#whatever",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cred := f.credential(t, ctx, credType, map[string]any{"id": tc.subject, "fullName": "Alice Example"})
			_, err := h.VerifyAndExtract(t.Context(), string(f.present(t, cred, tc.verificationMethod)))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
