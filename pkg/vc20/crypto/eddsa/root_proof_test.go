package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func signDocument(t *testing.T, doc string, purpose string) (*credential.RDFCredential, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
	require.NoError(t, err)
	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       purpose,
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	return signed, pub
}

// TestRootProofGraphsAcrossSerializations: the answer comes from the RDF
// dataset, so it cannot depend on how the document was written down.
//
// That is the point of reading it there rather than from the JSON: a
// compact document may ALIAS "proof" and "proofValue" through its context, a
// directly expanded one need not label its root at all, and both are the
// same RDF. Each of those is a shape the JSON-level version got wrong.
func TestRootProofGraphsAcrossSerializations(t *testing.T) {
	const vp = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`

	signed, pub := signDocument(t, vp, "authentication")
	// Graph names are blank-node labels, which differ between
	// serializations of the same document - so the invariant checked across
	// forms is that each names exactly ONE proof graph and each verifies,
	// not that the labels match.
	require.Len(t, rootProofGraphs(signed), 1, "the signed document links exactly one proof of its own")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	expanded, err := json.Marshal(signed)
	require.NoError(t, err)
	require.Equal(t, byte('['), expanded[0])

	// Directly expanded, which unlike MarshalJSON need not label the root.
	var compactDoc any
	require.NoError(t, json.Unmarshal(compact, &compactDoc))
	directlyExpanded, err := ld.NewJsonLdProcessor().Expand(compactDoc, credential.NewJSONLDOptions(""))
	require.NoError(t, err)
	directBytes, err := json.Marshal(directlyExpanded)
	require.NoError(t, err)

	// An ALIASED compact document: same RDF, different spelling.
	aliased := `{
		"@context": ["https://www.w3.org/ns/credentials/v2", {"sig": {"@id": "https://w3id.org/security#proof", "@container": "@graph"}}],
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"sig": ` + rawProof(t, compact) + `
	}`

	for name, form := range map[string][]byte{
		"compact":            compact,
		"expanded":           expanded,
		"directly expanded":  directBytes,
		"aliased proof term": []byte(aliased),
	} {
		t.Run(name, func(t *testing.T) {
			reparsed, err := credential.NewRDFCredentialFromJSON(form, nil)
			require.NoError(t, err)
			require.Len(t, rootProofGraphs(reparsed), 1,
				"every serialization of one document links exactly one proof of its own")
			require.NoError(t, NewSuite().Verify(reparsed, pub),
				"and every one of them verifies")
		})
	}
}

// rawProof lifts the proof object out of a compact signed document.
func rawProof(t *testing.T, compact []byte) string {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	proof, ok := doc["proof"]
	require.True(t, ok)
	out, err := json.Marshal(proof)
	require.NoError(t, err)
	return string(out)
}

// TestRootProofGraphsIgnoreAnEmbeddedCredentialsProof: the whole point is
// telling the document's own proof from one further down.
func TestRootProofGraphsIgnoreAnEmbeddedCredentialsProof(t *testing.T) {
	const vpWithEmbeddedProofOnly = `{
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

	cred, err := credential.NewRDFCredentialFromJSON([]byte(vpWithEmbeddedProofOnly), nil)
	require.NoError(t, err)
	require.Empty(t, rootProofGraphs(cred),
		"a presentation with no proof of its own links none, whatever it carries")
}

// TestRootProofGraphsRefuseAnAmbiguousRoot: a node detached from the root
// is unreferenced too, so a document containing one does not say which node
// is its root - and a proof hanging off the detached node must not be
// mistaken for the document's own.
//
// This is not hypothetical: verification removes every proof when hashing,
// so relocating a proof link leaves the signed hash unchanged.
func TestRootProofGraphsRefuseAnAmbiguousRoot(t *testing.T) {
	const twoUnreferencedNodes = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@graph": [
			{
				"id": "urn:uuid:the-presentation",
				"type": ["VerifiablePresentation"],
				"holder": "did:example:holder"
			},
			{
				"id": "urn:uuid:detached",
				"type": ["VerifiablePresentation"],
				"holder": "did:example:someone-else",
				"proof": {
					"type": "DataIntegrityProof",
					"cryptosuite": "eddsa-rdfc-2022",
					"proofPurpose": "authentication",
					"verificationMethod": "did:example:signer#key-1",
					"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
				}
			}
		]
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(twoUnreferencedNodes), nil)
	require.NoError(t, err)

	// The fixture is only worth anything if the detached node really does
	// carry a proof the document could be tricked into using.
	require.Contains(t, mustNQuads(t, cred), "security#proofValue",
		"the detached node's proof must survive parsing")

	require.Empty(t, rootProofGraphs(cred),
		"two unreferenced nodes mean the document does not say which is its root")
}

func mustNQuads(t *testing.T, cred *credential.RDFCredential) string {
	t.Helper()
	nq, err := cred.NQuads()
	require.NoError(t, err)
	return nq
}

// TestVerifyRefusesAStubRootProof is the second shape of the misplaced-proof
// attack, and the reason selection is tied to the root's proof GRAPH rather
// than to a proofValue.
//
// Moving the full typed proof onto the embedded credential and leaving a
// root proof object carrying ONLY the same proofValue keeps the document
// hashing identically - verification removes every proof - and a search by
// value would find the moved, typed proof and verify it with the root's key.
//
// Confining the search to the graph the root links to defeats it: that graph
// holds a proofValue and no typed proof, so there is nothing to select.
func TestVerifyRefusesAStubRootProof(t *testing.T) {
	// Signed WITH the credential already embedded, so the attack changes
	// nothing but where the proof sits. A test that also adds the
	// credential would fail on the changed document rather than on the
	// selection, and prove nothing about either.
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}]
	}`, "authentication")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))

	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	proofValue, ok := proof["proofValue"].(string)
	require.True(t, ok)

	// Move the real, typed proof onto the embedded credential and leave a
	// stub at the root carrying only the value.
	embedded, ok := doc["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	credentialNode, ok := embedded[0].(map[string]any)
	require.True(t, ok)
	credentialNode["proof"] = proof
	doc["proof"] = map[string]any{"proofValue": proofValue}

	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
	require.NoError(t, err)

	// The stub really is what the root links to, or this proves nothing.
	require.Len(t, rootProofGraphs(reparsed), 1,
		"the root still links a proof graph - it is the CONTENT that is a stub")

	require.Error(t, NewSuite().Verify(reparsed, pub),
		"a root proof carrying only a value must not select a proof from elsewhere")
}

// TestRootProofGraphsOnlyAcceptsRemovablePredicates: the predicates this
// accepts as a root proof link have to be exactly the ones
// credential.CredentialWithoutProofForTypes removes.
//
// A link accepted here but not removed there leaves that proof in the
// hashed document, so verification cannot reproduce a signature computed
// with proofs removed - and a valid document is rejected. Widening the set
// here without widening removal is a break, not a tolerance.
func TestRootProofGraphsOnlyAcceptsRemovablePredicates(t *testing.T) {
	require.ElementsMatch(t, []string{
		"https://w3id.org/security#proof",
		"http://www.w3.org/ns/credentials#proof",
	}, proofPredicates,
		"keep this in step with CredentialWithoutProofForTypes in pkg/vc20/credential")

	// And a document linking its proof under an IRI removal does not strip
	// names no root proof, rather than being accepted and then failing to
	// hash.
	const unsupportedIRI = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"sig": {"@id": "https://www.w3.org/ns/credentials#proof", "@container": "@graph"}}],
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"sig": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"proofPurpose": "authentication",
			"verificationMethod": "did:example:signer#key-1",
			"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
		}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(unsupportedIRI), nil)
	require.NoError(t, err)
	require.Empty(t, rootProofGraphs(cred))
}

// TestVerifyAcceptsAPresentationWhoseIDIsTheHolder: `holder` is a node
// reference in the VC 2.0 context, so a presentation that sets id to the
// holder DID has an edge from the root to itself. Counting that as an
// incoming reference leaves the document with no root and rejects a
// perfectly good signature.
func TestVerifyAcceptsAPresentationWhoseIDIsTheHolder(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "did:example:holder",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`, "authentication")

	require.Len(t, rootProofGraphs(signed), 1,
		"a self-edge must not hide the root")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(compact, nil)
	require.NoError(t, err)
	require.NoError(t, NewSuite().Verify(reparsed, pub))
}

// TestVerifyAcceptsAReferenceCycle: an ordinary credential can contain one -
// the credential names its credentialSubject, and an @id-valued subject
// property names the credential back. Then NO subject has zero incoming
// edges, and a root rule that required that rejected a proof Sign had just
// produced.
func TestVerifyAcceptsAReferenceCycle(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"relatedCredential": {"@id": "https://example.org/relatedCredential", "@type": "@id"}}],
		"id": "urn:uuid:the-credential",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "urn:uuid:the-subject",
			"relatedCredential": "urn:uuid:the-credential"
		}
	}`, "assertionMethod")

	require.Len(t, rootProofGraphs(signed), 1,
		"a cycle must not hide the root")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(compact, nil)
	require.NoError(t, err)
	require.NoError(t, NewSuite().Verify(reparsed, pub))
}

// TestVerifyRefusesAProofMovedWithinACycle is the misplaced-proof attack
// once more, this time INSIDE the credential ↔ credentialSubject cycle.
//
// Both nodes are in the same source component, so "a member of the source
// component" was not enough: moving the credential's proof onto its subject
// node leaves the hash unchanged - CredentialWithoutProof removes the link
// wherever it sits - and the moved proof would verify for a credential that
// carries none of its own.
//
// The root has to BE the credential, said by its rdf:type.
func TestVerifyRefusesAProofMovedWithinACycle(t *testing.T) {
	// Two things this fixture has to do, or it proves nothing.
	//
	// The ids put the SUBJECT before the credential in sort order, so a
	// rule that picks a candidate by order rather than by what the node IS
	// would pick the node the proof was moved to.
	//
	// And the proof is relocated under an ALIASED term. `proof` in the VC
	// 2.0 context is scoped to the credential, so a plain
	// `credentialSubject.proof` is dropped on expansion and the document
	// loses the proof entirely - which refuses for the wrong reason. The
	// alias puts the same `security#proof` predicate on the subject node,
	// which survives, and which CredentialWithoutProof strips just the
	// same, so the hash is unchanged.
	const withAlias = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"relatedCredential": {"@id": "https://example.org/relatedCredential", "@type": "@id"},
			 "nodeProof": {"@id": "https://w3id.org/security#proof", "@container": "@graph"}}],
		"id": "urn:uuid:zzz-the-credential",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "urn:uuid:aaa-the-subject",
			"relatedCredential": "urn:uuid:zzz-the-credential"
		}
	}`

	signed, pub := signDocument(t, withAlias, "assertionMethod")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))

	proof, ok := doc["proof"]
	require.True(t, ok, "the credential must start out with its own proof")
	subject, ok := doc["credentialSubject"].(map[string]any)
	require.True(t, ok)

	subject["nodeProof"] = proof
	delete(doc, "proof")

	moved, err := json.Marshal(doc)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)

	// The relocated proof really is in the document, or the refusal below
	// would be about a missing proof rather than about whose it is.
	require.Contains(t, mustNQuads(t, reparsed), "security#proofValue",
		"the moved proof must survive parsing")

	require.Empty(t, rootProofGraphs(reparsed),
		"a proof on a node that is not the credential is not the credential's")
	require.Error(t, NewSuite().Verify(reparsed, pub))
}
