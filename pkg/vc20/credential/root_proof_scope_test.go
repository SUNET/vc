package credential

import (
	"encoding/json"
	"testing"

	"github.com/piprate/json-gold/ld"

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
	require.Contains(t, err.Error(), "once serialized through RDF")
}

// TestAnAnonymousRootPointedAtByReverseIsRefused: @reverse is the one way a
// node can be pointed AT without the pointing showing up as a reference to
// its @id - so an anonymous root can be referenced after flattening even
// though nothing in the compact form names it. The compact form then reads
// the anonymous node as the document and the flattened form reads the
// referring node, and with no name to compare the swap would be invisible.
func TestAnAnonymousRootPointedAtByReverseIsRefused(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"attaches": {"@reverse": "https://example.org/vocab#attaches", "@type": "@id"}}],
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"attaches": [{
			"id": "urn:uuid:other",
			"type": ["VerifiablePresentation"]
		}]
	}`), nil)
	require.NoError(t, err)

	// The switch is real, or this proves nothing: the compact form is about
	// an unnamed node and the flattened form about urn:uuid:other.
	compactRoot, _, _, err := cred.rootAndGraphs(cred.documentSource())
	require.NoError(t, err)
	require.Nil(t, compactRoot["@id"], "the root is anonymous as written")

	marshalled, err := cred.MarshalJSON()
	require.NoError(t, err)
	flatRoot, _, _, err := cred.rootAndGraphs(string(marshalled))
	require.NoError(t, err)
	require.Equal(t, "urn:uuid:other", flatRoot["@id"],
		"and the referring node is the root once flattened")

	require.Error(t, cred.CheckRootSurvivesFlattening(),
		"a document that names two different roots must not be signed")
}

// TestGraphNameWrittenTwiceIsMergedAndRemoved: two top-level entries may
// carry the same graph name. JSON-LD expansion keeps both and RDF
// conversion merges their triples into ONE named graph, so indexing by name
// and keeping the last silently dropped the rest from the document the
// signature covers while the verifier's parsed RDF still held them.
//
// Merged and removed together now: the proof link names a graph, and the
// graph is everything written under that name.
func TestGraphNameWrittenTwiceIsMergedAndRemoved(t *testing.T) {
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

	proofs, without, err := cred.RootProofs()
	require.NoError(t, err)
	require.Len(t, proofs, 1, "one name is one graph, however many entries write it")

	form, err := without.CanonicalForm()
	require.NoError(t, err)
	require.NotContains(t, form, "zREAL", "the proof is removed from what it secures")
	require.NotContains(t, form, "added beside the proof",
		"and so is everything else written under that graph name - it is part of the same graph")
}

// TestANodeWrittenTwiceIsOneCandidate: expanded JSON-LD may carry a node's
// properties across several top-level entries, and RDF conversion merges
// them. Treating them as separate candidates reported an ambiguous root for
// a document whose merged serialization reads perfectly well.
func TestANodeWrittenTwiceIsOneCandidate(t *testing.T) {
	const split = `[
		{
			"@id": "urn:uuid:the-credential",
			"@type": ["https://www.w3.org/2018/credentials#VerifiableCredential"]
		},
		{
			"@id": "urn:uuid:the-credential",
			"https://www.w3.org/2018/credentials#issuer": [{"@id": "did:example:issuer"}]
		}
	]`

	cred, err := NewRDFCredentialFromJSON([]byte(split), nil)
	require.NoError(t, err)

	root, nodes, _, err := cred.rootAndGraphs(cred.documentSource())
	require.NoError(t, err, "two entries naming one node are one candidate")
	require.Len(t, nodes, 1)
	require.Equal(t, "urn:uuid:the-credential", root["@id"])
	require.Contains(t, root, "https://www.w3.org/2018/credentials#issuer",
		"and the merged node carries what both entries said")
}

// TestRootProofsUsesTheCredentialsOptions: root selection re-expands the
// document, and has to do it under the options this credential was PARSED
// with. Expanding with a fresh default instead meant a credential created
// with its own document loader, expandContext, processing mode or base
// parsed successfully and then expanded differently - or not at all - on
// every Sign and Verify.
func TestRootProofsUsesTheCredentialsOptions(t *testing.T) {
	const privateContext = "https://example.org/a-context-only-this-loader-has"

	// A loader this credential carries and the global one does not.
	loader := ld.NewCachingDocumentLoader(GetGlobalLoader())
	var context any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"@context":{"ex":"https://example.org/keys#"}}`), &context))
	loader.AddDocument(privateContext, context)

	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = loader

	document := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2", "` + privateContext + `"],
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`)

	cred, err := NewRDFCredentialFromJSON(document, options)
	require.NoError(t, err, "the credential's own loader resolves the context")

	// The global loader cannot, or this would prove nothing.
	_, err = NewRDFCredentialFromJSON(document, nil)
	require.Error(t, err, "the context must be unreachable without that loader")

	_, _, err = cred.RootProofs()
	require.NoError(t, err, "root selection must re-expand under the same options")
}

// TestCompactRootProofMergesASplitProofNode: expanded JSON-LD may carry one
// proof node's properties across several entries of its graph - two wrappers
// with the same name have their graphs concatenated - and RDF conversion
// merges them into one node. Counting entries without merging refused a proof
// that is single by every measure that matters.
func TestCompactRootProofMergesASplitProofNode(t *testing.T) {
	split := map[string]any{
		"@graph": []any{
			map[string]any{
				"@id":   "_:proof",
				"@type": []any{"https://w3id.org/security#DataIntegrityProof"},
			},
			map[string]any{
				"@id": "_:proof",
				"https://w3id.org/security#proofValue": []any{
					map[string]any{"@value": "zSignature"},
				},
			},
		},
	}

	proof, err := CompactRootProof(split)
	require.NoError(t, err, "a node split across graph entries is still one proof")
	require.True(t, HasProofType(proof, ProofTypeDataIntegrity),
		"the type from the first entry survives the merge")
	require.Equal(t, "zSignature", proof["https://w3id.org/security#proofValue"],
		"and so does the signature from the second")

	// Two genuinely different proof nodes are still refused.
	two := map[string]any{
		"@graph": []any{
			map[string]any{"@id": "_:a", "@type": []any{"https://w3id.org/security#DataIntegrityProof"}},
			map[string]any{"@id": "_:b", "@type": []any{"https://w3id.org/security#DataIntegrityProof"}},
		},
	}
	_, err = CompactRootProof(two)
	require.ErrorContains(t, err, "rather than one")
}

// TestCompactRootProofDoesNotMutateItsInput: SecuredDocument memoizes the
// root proofs and hands the same nodes to every caller, so CompactRootProof
// has to be read-only. Coalescing merges into the first map it sees for an id,
// which made compacting the same candidate twice - as the ecdsa suite does,
// once to match the offered proof and once to verify it - merge a split proof
// into the cache twice and accumulate duplicate values.
func TestCompactRootProofDoesNotMutateItsInput(t *testing.T) {
	first := map[string]any{
		"@id":   "_:proof",
		"@type": []any{"https://w3id.org/security#DataIntegrityProof"},
	}
	second := map[string]any{
		"@id": "_:proof",
		"https://w3id.org/security#proofValue": []any{
			map[string]any{"@value": "zSignature"},
		},
	}
	split := map[string]any{"@graph": []any{first, second}}

	before := len(first)

	once, err := CompactRootProof(split)
	require.NoError(t, err)
	twice, err := CompactRootProof(split)
	require.NoError(t, err)

	require.Len(t, first, before,
		"the input node must come back untouched, or the cache is poisoned")
	require.Equal(t, once, twice,
		"and compacting the same proof twice must give the same proof")

	values, isList := twice["https://w3id.org/security#proofValue"].([]any)
	if isList {
		require.Len(t, values, 1, "no duplicate values accumulate across passes")
	}
}

// TestSecuredDocumentSurvivesConcurrentVerification: the memoized root proofs
// are shared by every caller, and verification compacts them. Two
// verifications of one credential at once must therefore not write to the same
// maps - run under -race, this is the check that says so.
func TestSecuredDocumentSurvivesConcurrentVerification(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:example:issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhmGQWmzBYdCVSAzeVCTt6QcLnLCHKPkyVpGqu9rWY"
		}
	}`), nil)
	require.NoError(t, err)

	const readers = 8
	results := make(chan string, readers)
	for range readers {
		go func() {
			proofs, _, err := SecuredDocument(cred)
			if err != nil || len(proofs) != 1 {
				results <- "secured document unreadable"
				return
			}
			proof, err := CompactRootProof(proofs[0])
			if err != nil {
				results <- err.Error()
				return
			}
			value, _ := proof["proofValue"].(string)
			results <- value
		}()
	}

	first := <-results
	require.NotEmpty(t, first)
	for range readers - 1 {
		require.Equal(t, first, <-results,
			"every reader must see the same proof, however many read at once")
	}
}
