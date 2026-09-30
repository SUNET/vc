package credential

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRelocatingAProofChangesTheSecuredDocument pins the invariant the
// cryptosuites' comments rest on.
//
// While hashing removed EVERY proof, the document a signature covered was
// the same wherever the proof sat - which is what made relocation work at
// all. Root-scoped hashing removes only the root's own proofs, so a proof
// moved onto an embedded credential stays IN the secured document and the
// hash changes.
//
// Selection refuses a moved proof before this matters. The two are
// independent, and this is the half that would still hold if selection were
// wrong.
func TestRelocatingAProofChangesTheSecuredDocument(t *testing.T) {
	const presentation = `{
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
		}],
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"proofPurpose": "authentication",
			"verificationMethod": "did:example:holder#key-1",
			"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
		}
	}`

	secured := func(t *testing.T, document string) string {
		t.Helper()
		cred, err := NewRDFCredentialFromJSON([]byte(document), nil)
		require.NoError(t, err)
		_, without, err := cred.RootProofs()
		require.NoError(t, err)
		form, err := without.CanonicalForm()
		require.NoError(t, err)
		return form
	}

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(presentation), &doc))
	embedded, ok := doc["verifiableCredential"].([]any)
	require.True(t, ok)
	embedded[0].(map[string]any)["proof"] = doc["proof"]
	delete(doc, "proof")
	moved, err := json.Marshal(doc)
	require.NoError(t, err)

	asSigned := secured(t, presentation)
	relocated := secured(t, string(moved))

	require.NotContains(t, asSigned, "security#proofValue",
		"the root's own proof is what the signature does not cover")
	require.Contains(t, relocated, "security#proofValue",
		"a proof moved onto an embedded credential is CONTENT, and stays in")
	require.NotEqual(t, asSigned, relocated,
		"so relocation changes the document the signature covers")
}

// TestABlankRootIsNotComparedLexically: blank-node labels are
// serialization-local. ToRDF relabels "_:root" through its own identifier
// issuer and MarshalJSON can return "_:b0", so comparing them as stable ids
// reports that the root moved when it did not.
func TestABlankRootIsNotComparedLexically(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "_:root",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`), nil)
	require.NoError(t, err)

	compactRoot, _, _, err := cred.rootAndGraphs(cred.documentSource())
	require.NoError(t, err)
	marshalled, err := cred.MarshalJSON()
	require.NoError(t, err)
	flatRoot, _, _, err := cred.rootAndGraphs(string(marshalled))
	require.NoError(t, err)

	// The fixture is only worth something if the two labels really do
	// differ - otherwise a lexical comparison would pass anyway.
	require.NotEqual(t, compactRoot["@id"], flatRoot["@id"],
		"the relabelling has to happen, or this proves nothing")

	require.NoError(t, cred.CheckRootSurvivesFlattening(),
		"the same blank node under two labels is the same root")
}

// TestABlankRootThatIsReferredToIsRefused: a blank root cannot be compared
// across serializations, so it is required to be referred to by nothing -
// which is what makes it the unreferenced node in the flattened form too. A
// blank root something points at could be swapped for another node there
// without this noticing.
func TestABlankRootThatIsReferredToIsRefused(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"attaches": {"@id": "https://example.org/vocab#attaches", "@type": "@id"}}],
		"id": "_:root",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"@included": [{
			"id": "urn:uuid:other",
			"type": ["VerifiablePresentation"],
			"attaches": "_:root"
		}]
	}`), nil)
	require.NoError(t, err)

	err = cred.CheckRootSurvivesFlattening()
	require.Error(t, err)
	require.Contains(t, err.Error(), "refers to that node")
}

// TestGraphNameCollisionIsRefused: two top-level entries may carry the same
// graph name. JSON-LD expansion keeps both and RDF conversion merges their
// triples, so keeping one per name dropped the rest from the document the
// signature covers while the verifier's parsed RDF still held them.
func TestGraphNameCollisionIsRefused(t *testing.T) {
	// Two graphs under one name, one of them the root's proof.
	const collided = `[
		{
			"@id": "urn:uuid:the-presentation",
			"@type": ["https://www.w3.org/2018/credentials#VerifiablePresentation"],
			"https://w3id.org/security#proof": [{"@id": "urn:uuid:the-graph"}]
		},
		{
			"@id": "urn:uuid:the-graph",
			"@graph": [{
				"@type": ["https://w3id.org/security#DataIntegrityProof"],
				"https://w3id.org/security#proofValue": [
					{"@type": "https://w3id.org/security#multibase", "@value": "zREAL"}
				]
			}]
		},
		{
			"@id": "urn:uuid:the-graph",
			"@graph": [{
				"@id": "urn:uuid:smuggled",
				"https://schema.org/name": [{"@value": "added beside the proof"}]
			}]
		}
	]`

	cred, err := NewRDFCredentialFromJSON([]byte(collided), nil)
	require.NoError(t, err)

	_, _, err = cred.RootProofs()
	require.Error(t, err, "which entry is the proof cannot be answered, so neither is removed")
	require.Contains(t, err.Error(), "urn:uuid:the-graph")
}
