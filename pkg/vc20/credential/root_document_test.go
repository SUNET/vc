package credential

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/piprate/json-gold/ld"

	"github.com/stretchr/testify/require"
)

func TestRootCompactedDocument(t *testing.T) {
	t.Run("a single node is already rooted", func(t *testing.T) {
		document := map[string]any{"id": "https://example.org/a", "proof": map[string]any{}}
		rooted, err := RootCompactedDocument(document, "", nil)
		require.NoError(t, err)
		require.Equal(t, document, rooted)
	})

	t.Run("the known root is promoted and the rest included", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"@graph": []any{
				map[string]any{"id": "https://example.org/subject", "name": "a subject"},
				map[string]any{"id": "https://example.org/credential", "credentialSubject": "https://example.org/subject"},
			},
		}, "https://example.org/credential", nil)
		require.NoError(t, err)

		require.Equal(t, "https://example.org/credential", rooted["id"])
		require.Equal(t, "https://www.w3.org/ns/credentials/v2", rooted["@context"])
		require.NotContains(t, rooted, "@graph")
		require.Equal(t, []any{
			map[string]any{"id": "https://example.org/subject", "name": "a subject"},
		}, rooted["@included"], "the other nodes stay in the same graph")
	})

	t.Run("without a known root the unreferenced node wins", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@graph": []any{
				map[string]any{"id": "https://example.org/subject"},
				map[string]any{"id": "https://example.org/credential", "credentialSubject": "https://example.org/subject"},
			},
		}, "", nil)
		require.NoError(t, err)
		require.Equal(t, "https://example.org/credential", rooted["id"])
	})

	t.Run("a known root that is gone is refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@graph": []any{map[string]any{"id": "https://example.org/subject"}},
		}, "https://example.org/credential", nil)
		require.ErrorContains(t, err, "no longer holds the node")

		// And the same when disclosure left exactly one node behind, so the
		// document is not a container at all.
		_, err = RootCompactedDocument(map[string]any{
			"id": "https://example.org/subject",
		}, "https://example.org/credential", nil)
		require.ErrorContains(t, err, "no longer holds the node")
	})

	t.Run("an ambiguous document is refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@graph": []any{
				map[string]any{"id": "https://example.org/a"},
				map[string]any{"id": "https://example.org/b"},
			},
		}, "", nil)
		require.ErrorContains(t, err, "more than one node nothing refers to")
	})

	t.Run("a context on the node survives when the container has none", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@graph": []any{
				map[string]any{"@context": "https://www.w3.org/ns/credentials/v2", "id": "https://example.org/credential"},
			},
		}, "", nil)
		require.NoError(t, err)
		require.Equal(t, "https://www.w3.org/ns/credentials/v2", rooted["@context"],
			"promoting a node must not drop the only context the document has")
	})
}

// TestRootCompactedDocumentIgnoresLiterals: in expanded JSON-LD a value
// object carries @value, and what it holds is a string the document SAYS -
// not a node it points at. Reading one as a reference marks the node it
// happens to name as referenced, and a document where some literal equals the
// root's identifier then has no unreferenced node left and is refused outright.
func TestRootCompactedDocumentIgnoresLiterals(t *testing.T) {
	rooted, err := RootCompactedDocument(map[string]any{
		"@graph": []any{
			map[string]any{
				"@id": "https://example.org/credential",
				"https://example.org/vocab#subject": []any{
					map[string]any{"@id": "https://example.org/subject"},
				},
			},
			map[string]any{
				"@id": "https://example.org/subject",
				// A literal that happens to read like the root's identifier.
				"https://example.org/vocab#note": []any{
					map[string]any{"@value": "https://example.org/credential"},
				},
			},
		},
	}, "", nil)
	require.NoError(t, err, "a literal must not count as a reference to the root")
	require.Equal(t, "https://example.org/credential", rooted["@id"])
}

// TestRootCompactedDocumentNormalisesTheRootID: knownRootID is read off the
// EXPANDED document, so it is always an absolute IRI, while compaction
// rewrites a node's identifier under the document's own context and may turn
// it into a term or a compact IRI. Comparing the two strings literally
// rejected a valid derivation purely because compaction changed the spelling.
func TestRootCompactedDocumentNormalisesTheRootID(t *testing.T) {
	context := map[string]any{"ex": "https://example.org/credentials/"}

	t.Run("in a graph container", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@context": context,
			"@graph": []any{
				map[string]any{"@id": "https://example.org/subject"},
				map[string]any{"@id": "ex:outer", "https://example.org/vocab#s": map[string]any{"@id": "https://example.org/subject"}},
			},
		}, "https://example.org/credentials/outer", nil)
		require.NoError(t, err, "a compact spelling names the same node")
		require.Equal(t, "ex:outer", rooted["@id"])
	})

	t.Run("as a single node", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@context": context,
			"@id":      "ex:outer",
		}, "https://example.org/credentials/outer", nil)
		require.NoError(t, err)
		require.Equal(t, "ex:outer", rooted["@id"])
	})

	t.Run("a genuinely different node is still refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@context": context,
			"@id":      "ex:someone-else",
		}, "https://example.org/credentials/outer", nil)
		require.ErrorContains(t, err, "no longer holds the node")
	})
}

// TestRootCompactedDocumentUsesTheGivenOptions: normalizing a compact root
// identifier means expanding it, and that expansion has to run under the
// options the credential was PARSED with. Under fresh defaults a context only
// the credential's own loader knows does not resolve, the identifier does not
// normalize, and a valid derivation is refused as if its root had vanished.
func TestRootCompactedDocumentUsesTheGivenOptions(t *testing.T) {
	const privateContext = "https://example.org/a-root-context-only-this-loader-has"

	loader := ld.NewCachingDocumentLoader(GetGlobalLoader())
	var context any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"@context":{"ex":"https://example.org/credentials/"}}`), &context))
	loader.AddDocument(privateContext, context)

	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = loader

	document := map[string]any{"@context": privateContext, "@id": "ex:outer"}

	rooted, err := RootCompactedDocument(document, "https://example.org/credentials/outer", options)
	require.NoError(t, err, "the credential's own loader resolves the context")
	require.Equal(t, "ex:outer", rooted["@id"])

	// And the global loader genuinely cannot, or this proves nothing.
	_, err = RootCompactedDocument(document, "https://example.org/credentials/outer", nil)
	require.Error(t, err, "the context must be unreachable without that loader")
}

// TestRootCompactedDocumentIgnoresCompactLiterals: in COMPACT JSON-LD a
// reference and a literal are the same Go string - a term declared
// "@type": "@id" writes a reference as a bare string, and so does any ordinary
// string-valued property. Reading every string as a reference marked a node
// referenced because some unrelated literal equalled its identifier, and the
// document was refused for saying nothing of the kind.
func TestRootCompactedDocumentIgnoresCompactLiterals(t *testing.T) {
	context := map[string]any{
		"subject": map[string]any{"@id": "https://example.org/vocab#subject", "@type": "@id"},
		"note":    "https://example.org/vocab#note",
		"id":      "@id",
	}

	rooted, err := RootCompactedDocument(map[string]any{
		"@context": context,
		"@graph": []any{
			map[string]any{
				"id":      "https://example.org/credential",
				"subject": "https://example.org/subject",
			},
			map[string]any{
				"id": "https://example.org/subject",
				// A LITERAL, not a reference - "note" is not id-coerced.
				"note": "https://example.org/credential",
			},
		},
	}, "", nil)
	require.NoError(t, err, "a literal must not count as a reference, compact or not")
	require.Equal(t, "https://example.org/credential", rooted["id"])
}

// TestProofKeysResolvesEveryTermFromOneParsedContext: this runs on an SD
// credential BEFORE its signature has been checked, so resolving each member
// separately turned a single request into a context-processing operation per
// property. The context is parsed once and every member looked up in it.
func TestProofKeysResolvesEveryTermFromOneParsedContext(t *testing.T) {
	var context any
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "@id",
		"type": "@type",
		"seal": "https://w3id.org/security#proof",
		"note": "https://example.org/vocab#note"
	}`), &context))

	node := map[string]any{
		"id":   "https://example.org/credential",
		"type": "VerifiableCredential",
		"note": "kept",
		"seal": map[string]any{"type": "DataIntegrityProof"},
	}
	// Plenty of unrelated members, the shape that made per-member expansion
	// expensive.
	for i := range 50 {
		node[fmt.Sprintf("https://example.org/vocab#filler%d", i)] = "x"
	}

	require.Equal(t, []string{"seal"}, ProofKeys(node, context, nil),
		"the aliased proof term is found, and the keyword aliases do not break the probe")
}

// TestProofKeysRespectsAContextThatRemapsProof: "proof" is only the name the
// VC 2.0 context gives the security predicate. A document whose context points
// that name at an ordinary predicate is not carrying a proof there - RootProofs
// resolves the context and keeps the field, so removing it here would strip
// content the signature covers and the two would disagree about which quads
// that is.
func TestProofKeysRespectsAContextThatRemapsProof(t *testing.T) {
	t.Run("remapped to something else", func(t *testing.T) {
		var context any
		require.NoError(t, json.Unmarshal(
			[]byte(`{"proof": "https://example.org/vocab#proofreading"}`), &context))

		node := map[string]any{"proof": "checked by an editor"}
		require.Empty(t, ProofKeys(node, context, nil),
			"a remapped name is not the security predicate")
	})

	t.Run("aliased onto the predicate", func(t *testing.T) {
		var context any
		require.NoError(t, json.Unmarshal(
			[]byte(`{"seal": "https://w3id.org/security#proof"}`), &context))

		node := map[string]any{"seal": map[string]any{"type": "DataIntegrityProof"}}
		require.Equal(t, []string{"seal"}, ProofKeys(node, context, nil))
	})

	t.Run("the VC 2.0 context, which scopes proof by type", func(t *testing.T) {
		node := map[string]any{"proof": map[string]any{"type": "DataIntegrityProof"}}
		require.Equal(t, []string{"proof"},
			ProofKeys(node, "https://www.w3.org/ns/credentials/v2", nil),
			"no top-level definition means the ordinary meaning stands")
	})

	t.Run("no context at all", func(t *testing.T) {
		node := map[string]any{"proof": map[string]any{"type": "DataIntegrityProof"}}
		require.Equal(t, []string{"proof"}, ProofKeys(node, nil, nil))
	})
}

// TestProofKeysHonoursATypeScopedAlias: JSON-LD applies a TYPE-SCOPED context
// before expanding a node's members, so an alias defined in that scope is one
// RootProofs sees - it expands the whole document - and one a document-level
// lookup misses. The two would then disagree about which quads the signature
// covers.
func TestProofKeysHonoursATypeScopedAlias(t *testing.T) {
	var context any
	require.NoError(t, json.Unmarshal([]byte(`{
		"Sealed": {
			"@id": "https://example.org/vocab#Sealed",
			"@context": {"seal": "https://w3id.org/security#proof"}
		},
		"type": "@type",
		"id": "@id"
	}`), &context))

	t.Run("in scope", func(t *testing.T) {
		node := map[string]any{
			"id":   "https://example.org/credential",
			"type": "Sealed",
			"seal": map[string]any{"proofValue": "z..."},
		}
		require.Equal(t, []string{"seal"}, ProofKeys(node, context, nil),
			"the alias its own type brings into scope is a proof")
	})

	t.Run("out of scope", func(t *testing.T) {
		node := map[string]any{
			"id":   "https://example.org/credential",
			"seal": map[string]any{"proofValue": "z..."},
		}
		require.Empty(t, ProofKeys(node, context, nil),
			"without the type, the scoped definition does not apply")
	})
}

// TestProofKeysAppliesTypeScopedContextsInOrder: JSON-LD applies type-scoped
// contexts in LEXICOGRAPHIC order of the type names, so when two types define
// the same term there is a defined winner. Taking them in document order would
// let the order they happen to be written in decide which definition applies -
// and here, whether a member is the document's proof at all.
func TestProofKeysAppliesTypeScopedContextsInOrder(t *testing.T) {
	var context any
	require.NoError(t, json.Unmarshal([]byte(`{
		"AaaFirst": {
			"@id": "https://example.org/vocab#AaaFirst",
			"@context": {"seal": "https://w3id.org/security#proof"}
		},
		"ZzzLast": {
			"@id": "https://example.org/vocab#ZzzLast",
			"@context": {"seal": "https://example.org/vocab#wax"}
		},
		"type": "@type",
		"id": "@id"
	}`), &context))

	// ZzzLast sorts last, so its definition of "seal" wins - whichever
	// order the types are written in.
	for _, order := range [][]any{{"AaaFirst", "ZzzLast"}, {"ZzzLast", "AaaFirst"}} {
		node := map[string]any{
			"id":   "https://example.org/credential",
			"type": order,
			"seal": map[string]any{"proofValue": "z..."},
		}
		require.Empty(t, ProofKeys(node, context, nil),
			"the last type in sorted order decides, not the first in the document: %v", order)
	}
}

// TestRootOfExpandedNodesIgnoresAnIndexedGraph: a JSON-LD graph object may
// carry @index beside @graph and @id. Counting keys called an indexed proof
// graph a document node, so a credential that has one became ambiguously
// rooted and could not be verified at all. ld.IsGraph is the rule, and
// json-gold vendors it.
func TestRootOfExpandedNodesIgnoresAnIndexedGraph(t *testing.T) {
	// The graph is UNREFERENCED, which is the shape that discriminates: as a
	// graph it is not a candidate at all, while counted as a node it is a
	// second node nothing refers to and the document becomes ambiguous.
	expanded := []any{
		map[string]any{
			"@id":   "https://example.org/credential",
			"@type": []any{"https://www.w3.org/2018/credentials#VerifiableCredential"},
		},
		map[string]any{
			"@id":    "_:proofgraph",
			"@index": "the third proof",
			"@graph": []any{map[string]any{"@id": "_:p0"}},
		},
	}

	root, err := RootOfExpandedNodes(expanded)
	require.NoError(t, err, "an indexed graph is a graph, not a second root")
	require.Equal(t, "https://example.org/credential", root["@id"])
}

// TestRootCompactedDocumentUsesNodeLocalContexts: a top-level compact array
// has no shared context, but its nodes may each carry one. Bailing out on the
// shared context alone forced the string scan, which cannot tell an id-coerced
// value from an ordinary literal - so a literal equal to another node's id
// made that node look referenced and a valid document read as rootless.
func TestRootCompactedDocumentUsesNodeLocalContexts(t *testing.T) {
	rooted, err := RootCompactedDocument(map[string]any{
		"@graph": []any{
			map[string]any{
				"@context": map[string]any{
					"id":      "@id",
					"subject": map[string]any{"@id": "https://example.org/vocab#subject", "@type": "@id"},
				},
				"id":      "https://example.org/credential",
				"subject": "https://example.org/subject",
			},
			map[string]any{
				"@context": map[string]any{"id": "@id", "note": "https://example.org/vocab#note"},
				"id":       "https://example.org/subject",
				// A LITERAL that reads like the root's identifier.
				"note": "https://example.org/credential",
			},
		},
	}, "", nil)
	require.NoError(t, err, "node-local contexts tell a literal from a reference")
	require.Equal(t, "https://example.org/credential", rooted["id"])
}
