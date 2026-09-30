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

// rootProofsOf returns the proofs a document attaches to ITSELF - what
// Verify will consider - or nothing when the document does not say which
// node it is about.
func rootProofsOf(t *testing.T, cred *credential.RDFCredential) []any {
	t.Helper()
	proofs, _, err := cred.RootProofs()
	if err != nil {
		t.Logf("document names no root: %v", err)
		return nil
	}
	return proofs
}

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
	require.Len(t, rootProofsOf(t, signed), 1, "the signed document links exactly one proof of its own")

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
			require.Len(t, rootProofsOf(t, reparsed), 1,
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
	require.Empty(t, rootProofsOf(t, cred),
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

	require.Empty(t, rootProofsOf(t, cred),
		"two unreferenced nodes mean the document does not say which is its root")
}

func mustNQuads(t *testing.T, cred *credential.RDFCredential) string {
	t.Helper()
	nq, err := cred.NQuads()
	require.NoError(t, err)
	return nq
}

// TestVerifyRefusesAStubRootProof is the second shape of the misplaced-proof
// attack, and the reason selection is tied to the ROOT rather than to a
// proofValue found somewhere in the document.
//
// The full typed proof is moved onto the embedded credential and a stub
// carrying only the same proofValue is left at the root. A search by value
// would find the moved, typed proof and check it against the root's key.
//
// The refusal has to be the STUB being incomplete, not a signature
// mismatch. Root-scoped hashing retains the moved proof in the document, so
// an unqualified selector would fail too - just later, and for the wrong
// reason - and an assertion that merely required some error would no longer
// tell the two apart.
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

	// The stub really is what the root carries, or this proves nothing.
	require.Len(t, rootProofsOf(t, reparsed), 1,
		"the root still carries a proof - it is the CONTENT that is a stub")

	err = NewSuite().Verify(reparsed, pub)
	require.Error(t, err, "a root proof carrying only a value must not select a proof from elsewhere")
	require.Contains(t, err.Error(), ProofType,
		"the stub must be refused for being no proof at all; a signature mismatch here would mean the typed proof was found elsewhere and checked")
}

// TestTheProofsFoundAreTheProofsRemoved: the link this accepts as a root
// proof and the link removed from the hashed document have to be the same
// one. They used to be two lists in two packages, and a link accepted here
// but not removed there leaves that proof in the hashed document - so
// verification cannot reproduce the signature and a valid document is
// rejected.
//
// credential.RootProofs now does both in one pass, so they cannot drift.
// What is worth pinning is the consequence: a document linking its proof
// under the VC 1.1-era spelling is found AND removed, rather than found and
// left in.
func TestTheProofsFoundAreTheProofsRemoved(t *testing.T) {
	const legacySpelling = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"sig": {"@id": "https://www.w3.org/2018/credentials#proof", "@container": "@graph"}}],
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

	cred, err := credential.NewRDFCredentialFromJSON([]byte(legacySpelling), nil)
	require.NoError(t, err)

	proofs, without, err := cred.RootProofs()
	require.NoError(t, err)
	require.Len(t, proofs, 1, "the legacy spelling names a root proof")

	form, err := without.CanonicalForm()
	require.NoError(t, err)
	require.NotContains(t, form, "security#proofValue",
		"and the document it secures must not still contain it")
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

	require.Len(t, rootProofsOf(t, signed), 1,
		"a self-edge must not hide the root")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(compact, nil)
	require.NoError(t, err)
	require.NoError(t, NewSuite().Verify(reparsed, pub))
}

// TestVerifyTriesEveryRootProof: Sign APPENDS a proof rather than replacing
// one, so a document signed by two keys carries two root proofs. Checking
// only the first fails the second signature against its own public key -
// a valid document rejected, depending on which proof happened to come
// first.
func TestVerifyTriesEveryRootProof(t *testing.T) {
	const doc = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`

	firstPub, firstPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secondPub, secondPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
	require.NoError(t, err)
	once, err := NewSuite().Sign(cred, firstPriv, &SignOptions{
		VerificationMethod: "did:example:first#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	onceJSON, err := once.ToCompactJSON()
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(onceJSON, nil)
	require.NoError(t, err)
	twice, err := NewSuite().Sign(reparsed, secondPriv, &SignOptions{
		VerificationMethod: "did:example:second#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	twiceJSON, err := twice.ToCompactJSON()
	require.NoError(t, err)
	signedTwice, err := credential.NewRDFCredentialFromJSON(twiceJSON, nil)
	require.NoError(t, err)

	require.Len(t, rootProofsOf(t, signedTwice), 2,
		"the document must really carry two root proofs, or this proves nothing")

	for name, key := range map[string]ed25519.PublicKey{
		"the first signer":  firstPub,
		"the second signer": secondPub,
	} {
		t.Run(name, func(t *testing.T) {
			again, parseErr := credential.NewRDFCredentialFromJSON(twiceJSON, nil)
			require.NoError(t, parseErr)
			require.NoError(t, NewSuite().Verify(again, key),
				"each signer's own key must verify the document")
		})
	}

	// And a key that signed neither still fails.
	strangerPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	again, err := credential.NewRDFCredentialFromJSON(twiceJSON, nil)
	require.NoError(t, err)
	require.Error(t, NewSuite().Verify(again, strangerPub))
}

// cyclicPresentation embeds a credential whose subject links back to the
// presentation, so VP -> VC -> subject -> VP is one strongly connected
// component and every one of those nodes is a member of the single source.
const cyclicPresentation = `{
	"@context": ["https://www.w3.org/ns/credentials/v2",
		{"presentedIn": {"@id": "https://example.org/vocab#presentedIn", "@type": "@id"}}],
	"id": "urn:uuid:the-presentation",
	"type": ["VerifiablePresentation"],
	"holder": "did:example:holder",
	"verifiableCredential": [{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"presentedIn": {"@id": "https://example.org/vocab#presentedIn", "@type": "@id"}}],
		"id": "urn:uuid:the-credential",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "presentedIn": "urn:uuid:the-presentation"}
	}]
}`

// TestRootProofGraphsRefuseAnEmbeddedOnlyRoot: an UNTYPED outer node that
// embeds a credential which links back at it puts both in one source
// component, and only the credential is typed - so it was the lone
// candidate, and the "nothing to disambiguate" shortcut accepted it.
//
// That is the misplaced-proof attack again: removing every proof when
// hashing leaves the canonical form unchanged wherever the proof sits, so a
// proof moved from the wrapper onto the embedded credential verified with
// the wrapper's key.
func TestRootProofGraphsRefuseAnEmbeddedOnlyRoot(t *testing.T) {
	// "carries" is an ALIAS for the verifiableCredential predicate, typed
	// @id so the link lands in the DEFAULT graph the way the VCDM spelling
	// does. The wrapper carries no rdf:type, so only the credential is a
	// typed candidate; the subject's back-link puts the three in one source
	// component.
	const wrapperWithProofOnTheCredential = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{
				"carries": {"@id": "https://www.w3.org/2018/credentials#verifiableCredential", "@type": "@id"},
				"presentedIn": {"@id": "https://example.org/vocab#presentedIn", "@type": "@id"}
			}],
		"@graph": [
			{
				"id": "urn:uuid:the-wrapper",
				"carries": "urn:uuid:the-credential"
			},
			{
				"id": "urn:uuid:the-credential",
				"type": ["VerifiableCredential"],
				"issuer": "did:example:issuer",
				"credentialSubject": {"id": "did:example:subject", "presentedIn": "urn:uuid:the-wrapper"},
				"proof": {
					"type": "DataIntegrityProof",
					"cryptosuite": "eddsa-rdfc-2022",
					"proofPurpose": "assertionMethod",
					"verificationMethod": "did:example:issuer#key-1",
					"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
				}
			}
		]
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(wrapperWithProofOnTheCredential), nil)
	require.NoError(t, err)

	// The fixture is worth nothing unless the cycle and the proof both reach
	// the dataset - without the back-link the credential is simply an
	// embedded node with an incoming edge, which was never a candidate.
	nq := mustNQuads(t, cred)
	require.Contains(t, nq, "vocab#presentedIn", "the back-link must survive parsing")
	require.Contains(t, nq, "credentials#verifiableCredential", "and the aliased embedding link must expand to the real predicate")
	require.Contains(t, nq, "security#proofValue", "and so must the moved proof")

	require.Empty(t, rootProofsOf(t, cred),
		"a document whose only credential-typed node is one it carries does not say what it is")
}

// TestVerifyProofReturnsAProofWithItsSignature: verifyProofNode used to
// delete proofValue from the map it was handed and add an @context to it, so
// the proof VerifyProof returned was missing the signature it had just
// checked - an incomplete answer to "which proof verified".
func TestVerifyProofReturnsAProofWithItsSignature(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`, "authentication")

	proof, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err)
	require.NotNil(t, proof)

	value, ok := proof["proofValue"].(string)
	require.True(t, ok, "the verified proof must still carry the signature that was checked")
	require.NotEmpty(t, value)
	require.Equal(t, "authentication", proof["proofPurpose"])
	require.NotContains(t, proof, "@context", "and must not carry a context the document never wrote")
}

// TestSignAndVerifyACredentialThatIsItsOwnSubject: a credential may give
// itself and its credentialSubject the same id. That is a self-link, not an
// embedded document - but it made the credential the object of its own
// credentialSubject quad, so unembedded marked it contained and Verify
// refused a proof Sign had just produced.
func TestSignAndVerifyACredentialThatIsItsOwnSubject(t *testing.T) {
	const selfSubject = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "urn:uuid:the-credential",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "urn:uuid:the-credential"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(selfSubject), nil)
	require.NoError(t, err)
	require.Contains(t, mustNQuads(t, cred),
		"<urn:uuid:the-credential> <https://www.w3.org/2018/credentials#credentialSubject> <urn:uuid:the-credential>",
		"the self-link must reach the dataset, or this proves nothing")

	signed, pub := signDocument(t, selfSubject, "assertionMethod")
	require.Len(t, rootProofsOf(t, signed), 1, "a self-link contains nothing")
	require.NoError(t, NewSuite().Verify(signed, pub))
}

// TestVerifyRefusesAProofOfAnotherCryptosuite: the proof TYPE does not say
// which cryptosuite produced the signature, and VC20Handler dispatches on
// the first proof in the array while this suite may verify a later one - so
// what verified and what is reported could differ on the suite label.
func TestVerifyRefusesAProofOfAnotherCryptosuite(t *testing.T) {
	signed, pub := signDocument(t, `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`, "authentication")

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))

	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, Cryptosuite2022, proof["cryptosuite"], "the fixture must start as this suite's proof")
	proof["cryptosuite"] = "ecdsa-rdfc-2019"

	relabelled, err := json.Marshal(doc)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(relabelled, nil)
	require.NoError(t, err)

	// The root still LINKS a complete typed proof - it is the suite label
	// that disqualifies it, not the selection.
	require.Len(t, rootProofsOf(t, reparsed), 1)

	err = NewSuite().Verify(reparsed, pub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cryptosuite")
}

// TestSignRefusesADocumentWhoseRootDoesNotSurviveFlattening: a document
// whose root takes part in a reference cycle can be read one way and not
// another. Compact, its nesting says which node it is about; after
// MarshalJSON - which round-trips through N-Quads and FLATTENS - every node
// is lifted to the top level, and with the cycle none of them is
// unreferenced.
//
// Signing such a document would produce something this package verifies in
// one serialization and refuses in another. It is refused at signing
// instead, where the operator can still change the document. These shapes
// used to sign and verify while compact, which is the behaviour this
// replaces.
func TestSignRefusesADocumentWhoseRootDoesNotSurviveFlattening(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub

	for name, doc := range map[string]string{
		// A presentation whose embedded credential's subject links back.
		"a presentation its credential points back at": cyclicPresentation,
		// A credential whose subject is itself a credential, linking back.
		"a credential whose subject is a credential": `{
			"@context": ["https://www.w3.org/ns/credentials/v2",
				{"endorses": {"@id": "https://example.org/vocab#endorses", "@type": "@id"}}],
			"id": "urn:uuid:the-endorsement",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:endorser",
			"credentialSubject": {
				"id": "urn:uuid:the-endorsed",
				"type": ["VerifiableCredential"],
				"issuer": "did:example:issuer",
				"endorses": "urn:uuid:the-endorsement"
			}
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
			require.NoError(t, err)

			// The document reads fine as written - it is the SERIALIZED
			// form that loses the root, which is what makes this worth
			// refusing rather than merely failing later.
			_, _, err = cred.RootProofs()
			require.NoError(t, err, "compact, the document says which node it is about")

			_, err = NewSuite().Sign(cred, priv, &SignOptions{
				VerificationMethod: "did:example:signer#key-1",
				ProofPurpose:       "assertionMethod",
				Created:            time.Now().UTC(),
			})
			require.Error(t, err, "and serialized, it does not")
			require.Contains(t, err.Error(), "does not say which node it is about")
		})
	}

	// The contrast: a self-link is not a cycle, and a credential that gives
	// itself and its subject the same id still signs.
	t.Run("a self-link is not a cycle", func(t *testing.T) {
		signed, pub := signDocument(t, `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"id": "urn:uuid:the-credential",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "urn:uuid:the-credential"}
		}`, "assertionMethod")
		require.NoError(t, NewSuite().Verify(signed, pub))
	})
}
