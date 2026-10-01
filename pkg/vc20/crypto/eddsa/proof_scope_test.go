package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// TestVerifyRefusesAnUnboundedProofSet: the cap is not the handler's alone.
// A suite is callable directly, and the work it does per candidate - a JSON-LD
// canonicalization plus a signature check - is paid before anything about the
// document has been authenticated, whoever is asking.
func TestVerifyRefusesAnUnboundedProofSet(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	base, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(base, key, &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(compact, &document))

	genuine, ok := document["proof"].(map[string]any)
	require.True(t, ok)

	proofs := []any{genuine}
	for i := 0; i < credential.MaxRootProofs; i++ {
		filler := map[string]any{}
		for k, v := range genuine {
			filler[k] = v
		}
		filler["domain"] = fmt.Sprintf("https://example.org/%d", i)
		proofs = append(proofs, filler)
	}
	document["proof"] = proofs

	overfull, err := json.Marshal(document)
	require.NoError(t, err)
	cred, err := credential.NewRDFCredentialFromJSON(overfull, nil)
	require.NoError(t, err)

	_, err = NewSuite().VerifyProof(cred, pub)
	require.ErrorContains(t, err, "more than the 32 this will verify",
		"a document may not make a verifier do unbounded work, handler or not")
}

// TestSignAndVerifyABlankCredentialThatIsItsOwnSubject: a node that names
// ITSELF is still the node nothing else refers to, before and after
// flattening alike - rootOf has never counted a self-link, and the
// root-stability check must not either. It did, so the blank-node form of a
// credential whose subject is the credential could not be signed at all.
func TestSignAndVerifyABlankCredentialThatIsItsOwnSubject(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// No "id" on the credential, and a subject that points back at it by
	// blank node label.
	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@id": "_:root",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"@id": "_:root"}
	}`), nil)
	require.NoError(t, err)

	rootID, err := cred.RootID()
	require.NoError(t, err)
	require.Empty(t, rootID, "the root must really be blank, or this proves nothing")

	signed, err := NewSuite().Sign(cred, key, &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err, "a self-link is not another node referring to the root")

	_, err = NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err)
}

// TestSignRefusesToExceedTheProofLimit: an uncapped Sign appended a 33rd
// proof, returned success, and handed back a document this same library then
// refuses before checking any signature. An API that produces output it
// cannot read is worse than one that says no.
func TestSignRefusesToExceedTheProofLimit(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	base, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed := base
	for i := range credential.MaxRootProofs {
		signed, err = NewSuite().Sign(signed, key, &SignOptions{
			VerificationMethod: "did:example:issuer#key-1",
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
			Domain:             fmt.Sprintf("https://example.org/%d", i),
		})
		require.NoError(t, err, "signature %d is within the limit", i+1)
	}

	_, err = NewSuite().Sign(signed, key, &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
		Domain:             "https://example.org/one-too-many",
	})
	require.ErrorContains(t, err, "is the most this will verify",
		"signing must not produce a document this library refuses")
}

// TestSignRefusesABlankRootReferencedByAnAnonymousNode: an ANONYMOUS nested
// node is still a node. Letting it inherit the enclosing identity made its
// reference back to a blank-named root look like a self-link - and flattening
// then turns that node into a separate blank node, the original root stops
// being the unreferenced one, and because both names are blank the switch
// passes unnoticed. A proof relocated onto the new root secures the same
// unsecured RDF, which is the attack the root-stability check exists to stop.
func TestSignRefusesABlankRootReferencedByAnAnonymousNode(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// @included, so the nested node is a SIBLING once flattened rather than
	// a reference target - which leaves the flattened form with exactly one
	// unreferenced node, the formerly-nested one. The root has moved.
	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@id": "_:root",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"@included": [
			{"https://example.org/vocab#about": {"@id": "_:root"}}
		]
	}`), nil)
	require.NoError(t, err)

	_, err = NewSuite().Sign(cred, key, &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.ErrorContains(t, err, "something in it refers to that node",
		"an anonymous node pointing at the root is another node referring to it")
}

// TestSignAttachesAProofThisLibraryCanRead: "proof" is only the v2 context's
// name for the predicate. A document that REMAPS it to an ordinary property
// had the signature written under that property, so the signed document
// carried no root proof at all and this library could not verify what it had
// just produced.
func TestSignAttachesAProofThisLibraryCanRead(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The key SELECTION is what this fixes, and it is what is asserted here.
	// A document that remaps "proof" to an ordinary property must not have
	// the signature written under it - ProofKeyFor returns the absolute
	// predicate instead, which expands correctly under any context.
	//
	// Round-tripping such a document through Sign and VerifyProof is NOT
	// asserted: it still fails with a signature mismatch. Narrowed as far
	// as this - the document hash is identical at signing and verification,
	// and the proof configuration canonicalizes identically too, so the
	// divergence is in neither of the two inputs to the signature and I did
	// not find where it is. Under the VC 2.0
	// context the case cannot arise at all - its type-scoped context pins
	// "proof" to the security predicate for a VerifiableCredential node and
	// its terms are @protected - so this is about documents that do not use
	// v2.
	t.Run("a context that remaps proof", func(t *testing.T) {
		var remapping any
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "@id",
			"proof": "https://example.org/vocab#proofreading"
		}`), &remapping))

		node := map[string]any{"id": "https://example.org/credential"}
		require.Equal(t, credential.ProofPredicate,
			credential.ProofKeyFor(node, remapping, nil),
			"a remapped name must not be where a signature is written")

		// And where the name does mean the predicate, it is used.
		require.Equal(t, "proof", credential.ProofKeyFor(
			map[string]any{"type": []any{"VerifiableCredential"}},
			"https://www.w3.org/ns/credentials/v2", nil))
	})

	t.Run("a context that aliases proof", func(t *testing.T) {
		cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
			"@context": ["https://www.w3.org/ns/credentials/v2",
				{"seal": {"@id": "https://w3id.org/security#proof", "@container": "@graph"}}],
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"},
			"seal": {
				"type": "DataIntegrityProof",
				"cryptosuite": "eddsa-rdfc-2022",
				"created": "2020-01-01T00:00:00Z",
				"verificationMethod": "did:example:issuer#key-0",
				"proofPurpose": "assertionMethod",
				"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
			}
		}`), nil)
		require.NoError(t, err)

		signed, err := NewSuite().Sign(cred, key, &SignOptions{
			VerificationMethod: "did:example:issuer#key-1",
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
		})
		require.NoError(t, err)

		compact, err := signed.ToCompactJSON()
		require.NoError(t, err)
		var document map[string]any
		require.NoError(t, json.Unmarshal(compact, &document))
		require.NotContains(t, document, "proof",
			"the new proof joins the existing set under the name this document uses")

		_, err = NewSuite().VerifyProof(signed, pub)
		require.NoError(t, err)
	})
}
