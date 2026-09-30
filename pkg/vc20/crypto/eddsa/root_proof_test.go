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

// TestRootProofValuesAcrossSerializations: the answer comes from the RDF
// dataset, so it cannot depend on how the document was written down.
//
// That is the point of reading it there rather than from the JSON: a
// compact document may ALIAS "proof" and "proofValue" through its context, a
// directly expanded one need not label its root at all, and both are the
// same RDF. Each of those is a shape the JSON-level version got wrong.
func TestRootProofValuesAcrossSerializations(t *testing.T) {
	const vp = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`

	signed, pub := signDocument(t, vp, "authentication")
	want := rootProofValues(signed)
	require.Len(t, want, 1, "the signed document names exactly one proof of its own")

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
			require.Equal(t, want, rootProofValues(reparsed),
				"every serialization of one document names the same proof")
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

// TestRootProofValuesIgnoresAnEmbeddedCredentialsProof: the whole point is
// telling the document's own proof from one further down.
func TestRootProofValuesIgnoresAnEmbeddedCredentialsProof(t *testing.T) {
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
	require.Empty(t, rootProofValues(cred),
		"a presentation with no proof of its own names none, whatever it carries")
}

// TestRootProofValuesRefusesAnAmbiguousRoot: a node detached from the root
// is unreferenced too, so a document containing one does not say which node
// is its root - and a proof hanging off the detached node must not be
// mistaken for the document's own.
//
// This is not hypothetical: verification removes every proof when hashing,
// so relocating a proof link leaves the signed hash unchanged.
func TestRootProofValuesRefusesAnAmbiguousRoot(t *testing.T) {
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

	require.Empty(t, rootProofValues(cred),
		"two unreferenced nodes mean the document does not say which is its root")
}

func mustNQuads(t *testing.T, cred *credential.RDFCredential) string {
	t.Helper()
	nq, err := cred.NQuads()
	require.NoError(t, err)
	return nq
}
