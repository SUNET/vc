package eddsa

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestVerifyRefusesAProofMovedOntoACustomLinkedCredential is the shape no
// graph-shaped guess at the root could handle: a presentation that links a
// credential through a CUSTOM property, whose subject links back. Its RDF is
// isomorphic to a credential whose subject is itself a credential linking
// back, so no rule over a fixed predicate list can accept one and refuse the
// other.
//
// Reading the root off the document answers it: Sign attaches its proof to
// the top-level node, so a proof found anywhere else is not the document's
// own.
func TestVerifyRefusesAProofMovedOntoACustomLinkedCredential(t *testing.T) {
	const presentation = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"attaches": {"@id": "https://example.org/vocab#attaches"}}],
		"id": "urn:uuid:a",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"attaches": {
			"id": "urn:uuid:b",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "urn:uuid:a"}
		}
	}`

	signed, pub := signDocument(t, presentation, "authentication")
	require.NoError(t, NewSuite().Verify(signed, pub),
		"the document Sign just produced must verify")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	attached, ok := doc["attaches"].(map[string]any)
	require.True(t, ok)
	require.NotNil(t, doc["proof"], "the proof starts on the presentation")

	// Move it onto the credential the presentation links.
	attached["proof"] = doc["proof"]
	delete(doc, "proof")
	moved, err := json.Marshal(doc)
	require.NoError(t, err)

	relocated, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)
	require.Error(t, NewSuite().Verify(relocated, pub),
		"a proof the top-level node does not carry is not the document's own")
}

// TestPresentationSignatureCoversTheEmbeddedIssuerProof: removing EVERY
// proof when hashing meant a presentation's signature did not cover the
// issuer proof of the credential it carries, so that proof could be swapped
// or stripped and the presentation still verified. A proof secures the
// document it is attached to, and an embedded credential's proof is part of
// that document.
func TestPresentationSignatureCoversTheEmbeddedIssuerProof(t *testing.T) {
	const vpWithSignedVC = `{
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
				"cryptosuite": "eddsa-rdfc-2022",
				"proofPurpose": "assertionMethod",
				"verificationMethod": "did:example:issuer#key-1",
				"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
			}
		}]
	}`

	signed, pub := signDocument(t, vpWithSignedVC, "authentication")
	require.NoError(t, NewSuite().Verify(signed, pub))

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	strip := func(t *testing.T, mutate func(credential map[string]any)) *credential.RDFCredential {
		t.Helper()
		var doc map[string]any
		require.NoError(t, json.Unmarshal(compact, &doc))
		embedded, ok := doc["verifiableCredential"].([]any)
		require.True(t, ok)
		require.Len(t, embedded, 1)
		mutate(embedded[0].(map[string]any))

		tampered, err := json.Marshal(doc)
		require.NoError(t, err)
		reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
		require.NoError(t, err)
		return reparsed
	}

	t.Run("the issuer proof cannot be stripped", func(t *testing.T) {
		require.Error(t, NewSuite().Verify(strip(t, func(c map[string]any) {
			delete(c, "proof")
		}), pub))
	})

	t.Run("the issuer proof cannot be swapped", func(t *testing.T) {
		require.Error(t, NewSuite().Verify(strip(t, func(c map[string]any) {
			proof := c["proof"].(map[string]any)
			proof["verificationMethod"] = "did:example:someone-else#key-1"
		}), pub))
	})

	// And the presentation's own proof is still the one being checked: the
	// embedded credential's proof is CONTENT here, not a candidate.
	t.Run("the embedded proof is not offered as the document's own", func(t *testing.T) {
		proof, err := NewSuite().VerifyProof(signed, pub)
		require.NoError(t, err)
		require.Equal(t, "authentication", proof["proofPurpose"])
		require.Equal(t, "did:example:signer#key-1", proof["verificationMethod"])
	})
}
