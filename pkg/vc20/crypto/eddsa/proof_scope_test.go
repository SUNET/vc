package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestVerifyRefusesAProofMovedOntoACustomLinkedCredential is the shape no
// graph-shaped guess at the root could handle: a presentation that links a
// credential through a CUSTOM property no containment list knows. The old
// rule read only verifiableCredential and credentialSubject, so it could
// not tell this credential was carried - and with a link back it could not
// have told this document from a credential whose subject is itself a
// credential, whose RDF is isomorphic.
//
// Reading the root off the document answers it without a list: Sign
// attaches its proof to the top-level node, so a proof found anywhere else
// is not the document's own.
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
			"credentialSubject": {"id": "did:example:subject"}
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

// TestVerifyRefusesARootLinkedNodeThatIsNotAProof: the previous selection
// went through FindProofNode, which filtered on the proof TYPE. Reading the
// root's links directly would otherwise accept any node the root points at
// that happens to declare this cryptosuite, whatever it claims to be.
func TestVerifyRefusesARootLinkedNodeThatIsNotAProof(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`, "authentication")
	require.NoError(t, NewSuite().Verify(signed, pub))

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))

	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, ProofType, proof["type"], "the fixture must start as a typed proof")
	proof["type"] = "SomethingElse"

	retyped, err := json.Marshal(doc)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(retyped, nil)
	require.NoError(t, err)

	err = NewSuite().Verify(reparsed, pub)
	require.Error(t, err, "a node that is not a DataIntegrityProof is not a proof")
	require.Contains(t, err.Error(), ProofType)
}

// TestSignRefusesADocumentWhoseRootMOVESWhenFlattened: a node reachable only
// through @included is part of the document while compact and a top-level
// node once flattened. If it points AT the root, the flattened form has the
// root referenced and the included node referenced by nothing - so the two
// serializations name different documents.
//
// Checking that a root still EXISTS after flattening is not enough: it has
// to be the same one. Otherwise a proof moved onto the included node would
// verify as that node's own, since the same proof is removed from the same
// RDF either way.
func TestSignRefusesADocumentWhoseRootMOVESWhenFlattened(t *testing.T) {
	const switched = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"attaches": {"@id": "https://example.org/vocab#attaches", "@type": "@id"}}],
		"id": "urn:uuid:a",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"@included": [{
			"id": "urn:uuid:b",
			"type": ["VerifiablePresentation"],
			"attaches": "urn:uuid:a"
		}]
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(switched), nil)
	require.NoError(t, err)

	// Compact, the document says it is about A - which is what makes this
	// worth refusing rather than merely failing later.
	root, _, err := cred.RootProofs()
	require.NoError(t, err)
	require.Empty(t, root, "unsigned, so no proofs yet")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.Error(t, err, "a document that names two different roots must not be signed")
	require.Contains(t, err.Error(), "urn:uuid:a")
	require.Contains(t, err.Error(), "urn:uuid:b")
}

// TestVerifyRefusesAProofMovedOntoAnIncludedNode is the relocation half of
// the same shape: the document is signed WITHOUT the included node, which
// is then added with the root's proof moved onto it.
func TestVerifyRefusesAProofMovedOntoAnIncludedNode(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "urn:uuid:a",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`, "authentication")
	require.NoError(t, NewSuite().Verify(signed, pub))

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	require.NotNil(t, doc["proof"])

	// Add a node that points at the root and carries the root's proof.
	doc["@context"] = []any{
		"https://www.w3.org/ns/credentials/v2",
		map[string]any{"attaches": map[string]any{"@id": "https://example.org/vocab#attaches", "@type": "@id"}},
	}
	doc["@included"] = []any{map[string]any{
		"id":       "urn:uuid:b",
		"type":     []any{"VerifiablePresentation"},
		"attaches": "urn:uuid:a",
		"proof":    doc["proof"],
	}}
	delete(doc, "proof")

	moved, err := json.Marshal(doc)
	require.NoError(t, err)
	relocated, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)

	require.Error(t, NewSuite().Verify(relocated, pub),
		"a proof on an included node is not the document's own")
}

// TestVerifyRefusesARerootedDocument is the relocation the signing-side
// check alone could not stop, because the holder controls the document
// after it is signed.
//
// A signed presentation carrying a credential is rewritten with the
// CREDENTIAL at the top level and the presentation pushed underneath it
// through @included, and the presentation's proof moved onto the credential.
// Removing the new root's proof then reproduces the original unsecured RDF -
// the same triples, the same canonical form - so the signature would verify
// as the credential's own.
//
// What gives it away is that the rewritten document names one root as
// written and another once serialized through RDF.
func TestVerifyRefusesARerootedDocument(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "urn:uuid:the-presentation",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"id": "urn:uuid:the-credential",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}]
	}`, "authentication")
	require.NoError(t, NewSuite().Verify(signed, pub))

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))

	embedded, ok := doc["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	credentialNode, ok := embedded[0].(map[string]any)
	require.True(t, ok)
	proof := doc["proof"]
	require.NotNil(t, proof)

	// The credential becomes the document, and the presentation - still
	// naming the credential, now by reference rather than by nesting, so
	// the RDF is unchanged - is carried under it.
	delete(doc, "proof")
	delete(doc, "@context")
	doc["verifiableCredential"] = []any{map[string]any{"id": "urn:uuid:the-credential"}}
	credentialNode["proof"] = proof
	credentialNode["@context"] = "https://www.w3.org/ns/credentials/v2"
	credentialNode["@included"] = []any{doc}

	rerooted, err := json.Marshal(credentialNode)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(rerooted, nil)
	require.NoError(t, err)

	err = NewSuite().Verify(reparsed, pub)
	require.Error(t, err, "a document that names two different roots must not verify")
	require.Contains(t, err.Error(), "once serialized through RDF")
}
