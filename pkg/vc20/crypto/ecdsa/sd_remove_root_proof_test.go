package ecdsa

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestRemoveRootProofKeepsNestedProofsInAFlattenedDocument: RDFCredential's
// JSON marshalling goes through FromRDF, which FLATTENS - an embedded
// credential is lifted into the same top-level array as the document that
// carries it. Treating every entry of that array as a root deleted the
// embedded credential's proof along with the document's own, which is exactly
// the quads root-scoped hashing exists to keep.
func TestRemoveRootProofKeepsNestedProofsInAFlattenedDocument(t *testing.T) {
	// The shape FromRDF produces: the outer credential and the credential it
	// carries, side by side, linked only by an id reference. EXPANDED, which
	// is what FromRDF emits - so @id, not a term some context would have to
	// define.
	flattened := []any{
		map[string]any{
			"@id":               "https://example.org/credentials/outer",
			"type":              "VerifiableCredential",
			"credentialSubject": "https://example.org/credentials/inner",
			"proof":             map[string]any{"type": "DataIntegrityProof", "proofValue": "outer"},
		},
		map[string]any{
			"@id":   "https://example.org/credentials/inner",
			"type":  "VerifiableCredential",
			"proof": map[string]any{"type": "DataIntegrityProof", "proofValue": "inner"},
		},
	}

	stripped, err := removeRootProof(flattened, nil)
	require.NoError(t, err)

	remaining, isList := stripped.([]any)
	require.True(t, isList)
	outer := remaining[0].(map[string]any)
	inner := remaining[1].(map[string]any)
	require.NotContains(t, outer, "proof", "the document's own proof is what gets removed")
	require.Contains(t, inner, "proof",
		"the carried credential's proof is content the outer signature covers")
}

// A flattened document that does not say which node it is about is refused
// rather than half-stripped.
func TestRemoveRootProofRefusesAnAmbiguousDocument(t *testing.T) {
	t.Run("two unreferenced nodes", func(t *testing.T) {
		document := []any{
			map[string]any{"@id": "https://example.org/a", "proof": map[string]any{}},
			map[string]any{"@id": "https://example.org/b", "proof": map[string]any{}},
		}
		_, err := removeRootProof(document, nil)
		require.ErrorContains(t, err, "more than one node nothing refers to")
		require.Contains(t, document[0].(map[string]any), "proof", "nothing is removed on a refusal")
		require.Contains(t, document[1].(map[string]any), "proof")
	})

	t.Run("a reference cycle", func(t *testing.T) {
		document := []any{
			map[string]any{"@id": "https://example.org/a", "rel": "https://example.org/b"},
			map[string]any{"@id": "https://example.org/b", "rel": "https://example.org/a"},
		}
		_, err := removeRootProof(document, nil)
		require.ErrorContains(t, err, "referred to by another")
	})
}

// A single node is the document, under either spelling of its proof link.
func TestRemoveRootProofHandlesASingleNode(t *testing.T) {
	var document any
	require.NoError(t, json.Unmarshal([]byte(`{
		"@id": "https://example.org/credentials/outer",
		"https://w3id.org/security#proof": {"type": "DataIntegrityProof"},
		"credentialSubject": {"proof": {"type": "DataIntegrityProof"}}
	}`), &document))

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err)

	node := stripped.(map[string]any)
	require.NotContains(t, node, "https://w3id.org/security#proof")
	require.Contains(t, node["credentialSubject"].(map[string]any), "proof",
		"a nested proof is never the document's own")
}

// TestSdRootProofsReportsWhyEveryCandidateWasSkipped: skipping a malformed
// candidate keeps an appended proof from denying verification, but it must not
// also turn "every proof on this document is malformed" into the message a
// document with no SD proof at all gets. The cause is what tells the two
// apart.
func TestSdRootProofsReportsWhyEveryCandidateWasSkipped(t *testing.T) {
	_, _, signed := signNestedProofCredential(t)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(signed.OriginalJSON()), &document))

	// Replace the only root proof with one whose graph will hold a second
	// subject once serialized, so nothing compactable is left.
	proof, ok := document["proof"].(map[string]any)
	require.True(t, ok)
	proof["@included"] = map[string]any{
		"id":                            "https://example.org/extra",
		"https://example.org/vocab#any": "a second subject in the proof graph",
	}

	compact, err := json.Marshal(document)
	require.NoError(t, err)
	parsed, err := credential.NewRDFCredentialFromJSON(compact, nil)
	require.NoError(t, err)
	// Proofs only become named graphs once serialized through RDF.
	flattened, err := json.Marshal(parsed)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(flattened, nil)
	require.NoError(t, err)

	_, err = sdRootProofs(reparsed)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "carries no ecdsa-sd-2023 proof of its own",
		"a document whose every proof is malformed is not a document with no proof")
	require.ErrorContains(t, err, "rather than one")
}

// TestRemoveRootProofResolvesAliasedAndLegacyProofTerms: "proof" is only the
// name the v2 context happens to give the term, and the legacy predicate has
// its own IRI. Matching raw spellings missed both - and the spelling the code
// DID carry for the legacy case, https://www.w3.org/ns/credentials#proof, is
// not a proof predicate at all, so an expanded document using the real one
// kept its root proof while RootProofs removed it. The two then disagreed
// about which quads the signature covers.
func TestRemoveRootProofResolvesAliasedAndLegacyProofTerms(t *testing.T) {
	t.Run("the predicate, expanded", func(t *testing.T) {
		node := map[string]any{
			"@id":                     "https://example.org/credential",
			credential.ProofPredicate: map[string]any{"@id": "_:proof"},
		}
		stripped, err := removeRootProof(node, nil)
		require.NoError(t, err)
		require.NotContains(t, stripped, credential.ProofPredicate)
	})

	t.Run("an IRI that is not a proof predicate", func(t *testing.T) {
		// https://www.w3.org/2018/credentials#proof is defined by neither
		// VC 1.1 nor VC 2.0 - both map "proof" to the security vocabulary.
		// Treating it as a proof took an ordinary property out of the
		// secured document, where its value could be changed or stripped
		// without invalidating any signature.
		const notAProof = "https://www.w3.org/2018/credentials#proof"
		node := map[string]any{
			"@id":     "https://example.org/credential",
			notAProof: map[string]any{"@value": "an ordinary property"},
		}
		stripped, err := removeRootProof(node, nil)
		require.NoError(t, err)
		require.Contains(t, stripped, notAProof,
			"an unrelated IRI stays in the document the signature covers")
	})

	t.Run("an aliased term", func(t *testing.T) {
		var document any
		require.NoError(t, json.Unmarshal([]byte(`{
			"@context": {"seal": "https://w3id.org/security#proof", "note": "https://example.org/vocab#note"},
			"id": "https://example.org/credential",
			"note": "kept",
			"seal": {"type": "DataIntegrityProof"}
		}`), &document))

		document, err := removeRootProof(document, nil)
		require.NoError(t, err)

		node := document.(map[string]any)
		require.NotContains(t, node, "seal", "an aliased proof term is still the document's proof")
		require.Contains(t, node, "note", "and nothing else is touched")
	})
}

// TestRemoveRootProofLeavesANamedGraphAlone: a node may carry @graph beside
// properties of its own. That is a named graph, and the node is still what the
// document is about - reaching into it removes a proof that is not the root's.
func TestRemoveRootProofLeavesANamedGraphAlone(t *testing.T) {
	var document any
	require.NoError(t, json.Unmarshal([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "https://example.org/credential",
		"proof": {"type": "DataIntegrityProof", "proofValue": "root"},
		"@graph": [
			{"id": "https://example.org/carried", "proof": {"type": "DataIntegrityProof", "proofValue": "carried"}}
		]
	}`), &document))

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err)

	node := stripped.(map[string]any)
	require.NotContains(t, node, "proof", "the root's own proof goes")
	carried := node["@graph"].([]any)[0].(map[string]any)
	require.Contains(t, carried, "proof", "a proof inside its named graph stays")
}

// TestRemoveRootProofKeepsTheContextWhenDescending: a compacted graph
// container keeps its @context on the CONTAINER, so recomputing the context
// after descending into @graph found none - and a proof written through an
// aliased term stopped being recognized, staying in a document that is
// supposed to be without it.
func TestRemoveRootProofKeepsTheContextWhenDescending(t *testing.T) {
	var document any
	require.NoError(t, json.Unmarshal([]byte(`{
		"@context": {"seal": "https://w3id.org/security#proof", "note": "https://example.org/vocab#note", "id": "@id"},
		"@graph": [
			{"id": "https://example.org/credential", "note": "kept", "seal": {"type": "DataIntegrityProof"}}
		]
	}`), &document))

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err)

	node := stripped.(map[string]any)["@graph"].([]any)[0].(map[string]any)
	require.NotContains(t, node, "seal",
		"the container's context must reach the node inside it")
	require.Contains(t, node, "note")
}

// TestRemoveRootProofDropsTheGraphTheRootProofNamed: in flattened JSON-LD a
// proof is a LINK to a named graph sitting beside the document, which is
// exactly what RDFCredential.MarshalJSON emits. Deleting the link alone left
// the proof's quads in a document that is supposed to be without them, so
// verification canonicalized proof quads no disclosed signature covers and a
// derived credential stopped verifying after a round trip.
func TestRemoveRootProofDropsTheGraphTheRootProofNamed(t *testing.T) {
	document := []any{
		map[string]any{
			"@id":                     "https://example.org/credentials/outer",
			credential.ProofPredicate: []any{map[string]any{"@id": "_:rootproof"}},
			"https://example.org/vocab#carries": []any{
				map[string]any{"@id": "https://example.org/credentials/inner"},
			},
		},
		map[string]any{
			"@id":    "_:rootproof",
			"@graph": []any{map[string]any{"@id": "_:p0", "https://w3id.org/security#proofValue": "root"}},
		},
		map[string]any{
			"@id":                     "https://example.org/credentials/inner",
			credential.ProofPredicate: []any{map[string]any{"@id": "_:nestedproof"}},
		},
		map[string]any{
			"@id":    "_:nestedproof",
			"@graph": []any{map[string]any{"@id": "_:p1", "https://w3id.org/security#proofValue": "nested"}},
		},
	}

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err)

	remaining, isList := stripped.([]any)
	require.True(t, isList)

	var names []string
	for _, entry := range remaining {
		node := entry.(map[string]any)
		id, _ := node["@id"].(string)
		names = append(names, id)
		if id == "https://example.org/credentials/outer" {
			require.NotContains(t, node, credential.ProofPredicate,
				"the root's proof LINK goes")
		}
	}

	require.NotContains(t, names, "_:rootproof",
		"and so does the graph it named, or its quads stay in the secured document")
	require.Contains(t, names, "_:nestedproof",
		"while a nested credential's proof graph is content the signature covers")
	require.Contains(t, names, "https://example.org/credentials/inner")
}

// TestRemoveRootProofUsesTheRootsOwnContext: a flattened compact array may
// give each node its own @context, and reordering top-level nodes does not
// change the RDF - so reading the FIRST context let array order decide whether
// the root's proof alias was recognized.
func TestRemoveRootProofUsesTheRootsOwnContext(t *testing.T) {
	// The embedded node comes FIRST and defines "seal" as something
	// harmless; the root defines it as the proof predicate.
	document := []any{
		map[string]any{
			"@context": map[string]any{"seal": "https://example.org/vocab#wax", "id": "@id"},
			"id":       "https://example.org/credentials/inner",
			"seal":     "red",
		},
		map[string]any{
			"@context": map[string]any{"seal": "https://w3id.org/security#proof", "carries": map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"}, "id": "@id"},
			"id":       "https://example.org/credentials/outer",
			"carries":  "https://example.org/credentials/inner",
			"seal":     map[string]any{"type": "DataIntegrityProof"},
		},
	}

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err)

	remaining := stripped.([]any)
	inner := remaining[0].(map[string]any)
	outer := remaining[1].(map[string]any)

	require.NotContains(t, outer, "seal",
		"the ROOT's context decides, whatever order the nodes came in")
	require.Contains(t, inner, "seal",
		"and a node whose own context means something else keeps its field")
}

// TestRemoveRootProofIgnoresGraphWrappersAsCandidates: RootProofs excludes
// named graph wrappers when selecting a root, so an UNREFERENCED named graph
// is perfectly good secured content there. Offering it as a root candidate
// here made the same document ambiguous, and SD signing and derivation failed
// on it.
func TestRemoveRootProofIgnoresGraphWrappersAsCandidates(t *testing.T) {
	document := []any{
		map[string]any{
			"@id":                     "https://example.org/credential",
			credential.ProofPredicate: []any{map[string]any{"@id": "_:rootproof"}},
		},
		map[string]any{
			"@id":    "_:rootproof",
			"@graph": []any{map[string]any{"@id": "_:p0"}},
		},
		// Referred to by nothing, and still not a candidate.
		map[string]any{
			"@id":    "_:loosegraph",
			"@graph": []any{map[string]any{"@id": "_:x", "https://example.org/vocab#n": "kept"}},
		},
	}

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err, "a loose named graph is content, not a second root")

	remaining := stripped.([]any)
	var names []string
	for _, entry := range remaining {
		node := entry.(map[string]any)
		id, _ := node["@id"].(string)
		names = append(names, id)
	}
	require.NotContains(t, names, "_:rootproof", "the root's own proof graph goes")
	require.Contains(t, names, "_:loosegraph", "an unrelated graph stays")
	require.NotContains(t, remaining[0].(map[string]any), credential.ProofPredicate)
}

// TestRemoveRootProofHandlesASplitRootNode: expanded JSON-LD may split one
// node across several top-level entries, which RDF conversion merges back into
// one. Treating each entry as its own node reported several unreferenced roots
// and refused the document; and once selection merges them, the proof may be
// written on ANY fragment, so every fragment of the chosen root has to be
// edited.
func TestRemoveRootProofHandlesASplitRootNode(t *testing.T) {
	document := []any{
		map[string]any{
			"@id":                     "https://example.org/credential",
			credential.ProofPredicate: []any{map[string]any{"@id": "_:rootproof"}},
		},
		map[string]any{
			"@id": "https://example.org/credential",
			"https://example.org/vocab#carries": []any{
				map[string]any{"@id": "https://example.org/inner"},
			},
		},
		map[string]any{
			"@id":                     "https://example.org/inner",
			credential.ProofPredicate: []any{map[string]any{"@id": "_:nestedproof"}},
		},
		map[string]any{"@id": "_:rootproof", "@graph": []any{map[string]any{"@id": "_:p0"}}},
		map[string]any{"@id": "_:nestedproof", "@graph": []any{map[string]any{"@id": "_:p1"}}},
	}

	stripped, err := removeRootProof(document, nil)
	require.NoError(t, err, "two entries sharing an id are one node, not two roots")

	remaining := stripped.([]any)
	var names []string
	for _, entry := range remaining {
		node := entry.(map[string]any)
		id, _ := node["@id"].(string)
		names = append(names, id)
		if id == "https://example.org/credential" {
			require.NotContains(t, node, credential.ProofPredicate,
				"the root's proof goes, on whichever fragment carries it")
		}
	}
	require.NotContains(t, names, "_:rootproof", "and the graph it named")
	require.Contains(t, names, "_:nestedproof", "while the nested credential keeps its own")
}

// TestRemoveRootProofComposesContexts: a node-local @context is applied ON TOP
// of the inherited one, not instead of it. Returning only the node's own
// dropped outer definitions - an outer alias for the proof predicate among
// them - so removeRootProof could leave a root proof that RootProofs removes,
// and SD signing and derivation would hash different documents.
func TestRemoveRootProofComposesContexts(t *testing.T) {
	t.Run("an outer alias survives a node's own context", func(t *testing.T) {
		var document any
		require.NoError(t, json.Unmarshal([]byte(`{
			"@context": {"seal": "https://w3id.org/security#proof", "id": "@id"},
			"@graph": [
				{
					"@context": {"note": "https://example.org/vocab#note"},
					"id": "https://example.org/credential",
					"note": "kept",
					"seal": {"type": "DataIntegrityProof"}
				}
			]
		}`), &document))

		stripped, err := removeRootProof(document, nil)
		require.NoError(t, err)

		node := stripped.(map[string]any)["@graph"].([]any)[0].(map[string]any)
		require.NotContains(t, node, "seal",
			"the container's alias still names the proof inside the node")
		require.Contains(t, node, "note")
	})

	t.Run("an explicit null resets", func(t *testing.T) {
		var document any
		require.NoError(t, json.Unmarshal([]byte(`{
			"@context": {"seal": "https://w3id.org/security#proof", "id": "@id"},
			"@graph": [
				{
					"@context": null,
					"id": "https://example.org/credential",
					"seal": {"type": "DataIntegrityProof"}
				}
			]
		}`), &document))

		stripped, err := removeRootProof(document, nil)
		require.NoError(t, err)

		node := stripped.(map[string]any)["@graph"].([]any)[0].(map[string]any)
		require.Contains(t, node, "seal",
			"a null context clears what was active, so the alias means nothing here")
	})
}
