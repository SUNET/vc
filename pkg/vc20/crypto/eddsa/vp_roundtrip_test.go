package eddsa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// signAndVerify signs doc and verifies the result, the way any caller does:
// the signed credential is serialized, re-parsed, and checked.
func signAndVerify(t *testing.T, doc, proofPurpose string) error {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       proofPurpose,
		Created:            time.Now().UTC(),
		Challenge:          "test-nonce",
		Domain:             "https://verifier.example.com",
	})
	require.NoError(t, err)

	signedJSON, err := json.Marshal(signed)
	require.NoError(t, err)

	reparsed, err := credential.NewRDFCredentialFromJSON(signedJSON, nil)
	require.NoError(t, err)

	return NewSuite().Verify(reparsed, pub)
}

// TestVerifyRoundTrip covers the serialization a caller actually produces:
// sign, marshal, re-parse, verify.
//
// The suite's existing TestSignAndVerify_VerifiablePresentation verifies a
// presentation carrying no credential, straight from Sign's return value.
// This one re-parses, which is where the target-type detection breaks down:
// OriginalJSON() is then EXPANDED JSON-LD - a JSON array - so the
// map[string]any unmarshal fails, the error is swallowed, and the target
// stays "VerifiableCredential". For a presentation that removes an embedded
// credential's issuer proof, if there is one, and leaves the presentation's
// OWN proof in the document being hashed.
//
// The credential-bearing half of the story is in
// openid4vp.TestVPBuilderEdDSAPresentationVerifies, which covers the
// builder's compact output.
func TestVerifyRoundTrip(t *testing.T) {
	tests := map[string]struct {
		doc     string
		purpose string
	}{
		"verifiable credential": {
			doc: `{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"type": ["VerifiableCredential"],
				"issuer": "did:example:issuer",
				"credentialSubject": {"id": "did:example:subject"}
			}`,
			purpose: "assertionMethod",
		},
		"verifiable presentation": {
			doc: `{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"type": ["VerifiablePresentation"],
				"holder": "did:example:holder"
			}`,
			purpose: "authentication",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, signAndVerify(t, tt.doc, tt.purpose))
		})
	}
}

// TestVerifyRejectsATamperedPresentation keeps the fix honest: verification
// has to still say no. Signing and verification agree because both remove
// the ROOT's own proofs and nothing else - an embedded credential's proof
// stays in the document the signature covers - and that agreement must not
// also make the document irrelevant to the signature.
func TestVerifyRejectsATamperedPresentation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:original-holder"
	}`), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
		Challenge:          "test-nonce",
		Domain:             "https://verifier.example.com",
	})
	require.NoError(t, err)

	signedJSON, err := json.Marshal(signed)
	require.NoError(t, err)

	// Change the holder, and nothing else - the verification method is a
	// different identifier on purpose, so the proof configuration is
	// untouched and only the document differs.
	tampered := bytes.ReplaceAll(signedJSON, []byte("original-holder"), []byte("someone-else"))
	require.NotEqual(t, signedJSON, tampered, "the tamper must actually change the document")

	reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
	require.NoError(t, err)

	require.Error(t, NewSuite().Verify(reparsed, pub),
		"a presentation whose holder was changed must not verify")
}

// TestVerifyRejectsTheWrongKey is the other half of not-vacuous.
func TestVerifyRejectsTheWrongKey(t *testing.T) {
	other, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`), nil)
	require.NoError(t, err)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:holder#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	signedJSON, err := json.Marshal(signed)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(signedJSON, nil)
	require.NoError(t, err)

	require.Error(t, NewSuite().Verify(reparsed, other))
}
