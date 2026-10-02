package ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// signPresentation signs a document with this suite and returns it compacted.
func signPresentation(t *testing.T, doc string) ([]byte, *ecdsa.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(context.Background(), cred, key, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, NewSuite().Verify(signed, &key.PublicKey),
		"the document Sign just produced must verify")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	return compact, &key.PublicKey
}

// TestVerifyRefusesAProofMovedOntoAnEmbeddedCredential: this suite searched
// the whole proof object for a proof of the right TYPE, and hashing removed
// every proof in the graph - so a proof moved from the presentation onto the
// credential it carries left the hashed document unchanged and verified
// against the holder's key as if the credential had carried it.
func TestVerifyRefusesAProofMovedOntoAnEmbeddedCredential(t *testing.T) {
	compact, pub := signPresentation(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}]
	}`)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	embedded, ok := doc["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	require.NotNil(t, doc["proof"], "the proof starts on the presentation")

	embedded[0].(map[string]any)["proof"] = doc["proof"]
	delete(doc, "proof")
	moved, err := json.Marshal(doc)
	require.NoError(t, err)

	relocated, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)
	require.Error(t, NewSuite().Verify(relocated, pub),
		"a proof the top-level node does not carry is not the document's own")
}

// TestPresentationSignatureCoversTheEmbeddedProof: removing EVERY proof when
// hashing meant a presentation's signature did not cover the proof of the
// credential it carries.
func TestPresentationSignatureCoversTheEmbeddedProof(t *testing.T) {
	compact, pub := signPresentation(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"},
			"proof": {
				"type": "DataIntegrityProof",
				"cryptosuite": "ecdsa-rdfc-2019",
				"proofPurpose": "assertionMethod",
				"verificationMethod": "did:example:issuer#key-1",
				"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
			}
		}]
	}`)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	embedded := doc["verifiableCredential"].([]any)
	delete(embedded[0].(map[string]any), "proof")

	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
	require.NoError(t, err)

	require.Error(t, NewSuite().Verify(reparsed, pub),
		"stripping the embedded credential's proof must change the document this signature covers")
}
