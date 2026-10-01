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

// TestRootCompactedDocumentNormalisesIDsBeforeLookup: once a document expands,
// the references it contains are absolute IRIs, while each node's own id is
// still spelled as the document writes it. Looking a compact id up in a set of
// absolute ones never matched, so every node looked unreferenced and a
// perfectly good document read as ambiguous.
func TestRootCompactedDocumentNormalisesIDsBeforeLookup(t *testing.T) {
	var context any
	require.NoError(t, json.Unmarshal([]byte(`{
		"ex": "https://example.org/things/",
		"id": "@id",
		"subject": {"@id": "https://example.org/vocab#subject", "@type": "@id"}
	}`), &context))

	rooted, err := RootCompactedDocument(map[string]any{
		"@context": context,
		"@graph": []any{
			map[string]any{"id": "ex:subject"},
			map[string]any{"id": "ex:credential", "subject": "ex:subject"},
		},
	}, "", nil)
	require.NoError(t, err,
		"the compact link names the compact node, however each is spelled")
	require.Equal(t, "ex:credential", rooted["id"])
}

// TestProofKeysRespectsAVocabulary: a context declaring @vocab and no explicit
// "proof" term expands the name through that vocabulary, to something which is
// not the security predicate. A term LOOKUP finds no definition, and falling
// back to the bare name then removed an ordinary property - in SD
// mandatory-pointer selection, letting a mandatory /proof value be dropped
// from a derivation.
func TestProofKeysRespectsAVocabulary(t *testing.T) {
	var vocabulary any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"@vocab": "https://example.org/vocab#", "id": "@id"}`), &vocabulary))

	node := map[string]any{
		"id":    "https://example.org/credential",
		"proof": map[string]any{"type": "a reading by an editor"},
	}
	require.Empty(t, ProofKeys(node, vocabulary, nil),
		"a vocabulary gives the name a meaning, and it is not the predicate")

	// With the vocabulary pointing AT the security term, it is a proof again.
	var pointed any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"proof": "https://w3id.org/security#proof", "id": "@id"}`), &pointed))
	require.Equal(t, []string{"proof"}, ProofKeys(node, pointed, nil))

	// And with nothing to resolve against, the bare name still stands.
	require.Equal(t, []string{"proof"}, ProofKeys(node, nil, nil))
}

// TestRootCompactedDocumentKeepsANamedGraphNode: a node carrying @graph beside
// its own id and properties is a named-graph NODE, and the document is about
// it. Treating any @graph as a bare container sent root selection inside that
// graph.
func TestRootCompactedDocumentKeepsANamedGraphNode(t *testing.T) {
	document := map[string]any{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id":       "https://example.org/credential",
		"type":     "VerifiableCredential",
		"@graph":   []any{map[string]any{"id": "https://example.org/inside"}},
	}

	rooted, err := RootCompactedDocument(document, "https://example.org/credential", nil)
	require.NoError(t, err, "the node is the root, not the graph it names")
	require.Equal(t, "https://example.org/credential", rooted["id"])
	require.Contains(t, rooted, "@graph", "and its graph stays where it is")
}

// TestRootCompactedDocumentKeepsBothContexts: JSON-LD applies a graph
// container's context and then the node's own, and the node's may define or
// override terms it uses. Keeping only the container's dropped those
// definitions, which changes or removes triples - in a helper whose whole
// promise is that the graph, and so the signature over it, is unchanged.
func TestRootCompactedDocumentKeepsBothContexts(t *testing.T) {
	rooted, err := RootCompactedDocument(map[string]any{
		"@context": map[string]any{"id": "@id"},
		"@graph": []any{
			map[string]any{
				"@context": map[string]any{"note": "https://example.org/vocab#note"},
				"id":       "https://example.org/credential",
				"note":     "defined only by the node's own context",
			},
		},
	}, "", nil)
	require.NoError(t, err)

	contexts, isList := rooted["@context"].([]any)
	require.True(t, isList, "both contexts survive, as a flat list")
	require.Len(t, contexts, 2)
	require.Equal(t, map[string]any{"id": "@id"}, contexts[0],
		"the container's context is applied first")
	require.Equal(t, map[string]any{"note": "https://example.org/vocab#note"}, contexts[1],
		"and the node's own after it")

	// The promoted document must still expand to the triple the node's
	// context defines - which is the point, not the shape of the array.
	expanded, err := ld.NewJsonLdProcessor().Expand(rooted, NewJSONLDOptions(""))
	require.NoError(t, err)
	encoded, err := json.Marshal(expanded)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "https://example.org/vocab#note",
		"the node's own definitions still produce their triples")
}

// TestRootCompactedDocumentIgnoresASelfLinkWithAContext: a node that names
// ITSELF is still the node nothing ELSE refers to. Collecting references into
// one set lost which node supplied each, so a self-link marked the root as
// referenced and the document read as rootless - while the no-context
// fallback, which tracks the source, got it right. Adding a context changed
// which node the document was about, which is the one thing root selection
// must never do.
func TestRootCompactedDocumentIgnoresASelfLinkWithAContext(t *testing.T) {
	var context any
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "@id",
		"note": "https://example.org/vocab#note",
		"about": {"@id": "https://example.org/vocab#about", "@type": "@id"},
		"carries": {"@id": "https://example.org/vocab#carries", "@type": "@id"}
	}`), &context))

	graph := []any{
		// A property of its own, or expansion drops it as free-floating and
		// the expanded reading is never exercised at all.
		map[string]any{"id": "https://example.org/other", "note": "kept"},
		map[string]any{
			"id":      "https://example.org/credential",
			"about":   "https://example.org/credential",
			"carries": "https://example.org/other",
		},
	}

	withContext, err := RootCompactedDocument(map[string]any{
		"@context": context,
		"@graph":   graph,
	}, "", nil)
	require.NoError(t, err, "a self-link is not another node referring to the root")
	require.Equal(t, "https://example.org/credential", withContext["id"])

	// And the contextless reading of the same shape agrees, which is the
	// property that matters: a context must not move the root.
	withoutContext, err := RootCompactedDocument(map[string]any{"@graph": graph}, "", nil)
	require.NoError(t, err)
	require.Equal(t, withContext["id"], withoutContext["id"],
		"both readings must choose the same node")
}

// TestRootCompactedDocumentKeepsANullReset: an explicit node-local
// "@context": null RESETS the container's context in JSON-LD. Treating it as
// an absent context left the promoted node inheriting definitions it never
// had - more triples than the document carried, from a helper whose promise is
// that the graph is unchanged.
func TestRootCompactedDocumentKeepsANullReset(t *testing.T) {
	container := map[string]any{"note": "https://example.org/vocab#note", "id": "@id"}

	rooted, err := RootCompactedDocument(map[string]any{
		"@context": container,
		"@graph": []any{
			map[string]any{
				"@context": nil,
				"id":       "https://example.org/credential",
				"note":     "a plain string, not a predicate",
			},
		},
	}, "", nil)
	require.NoError(t, err)

	sequence, isList := rooted["@context"].([]any)
	require.True(t, isList, "the reset is kept in the sequence")
	require.Len(t, sequence, 2)
	require.Equal(t, container, sequence[0])
	require.Nil(t, sequence[1], "and it is the null that clears what came before")

	// The point is the RDF: with the reset kept, "note" defines nothing and
	// produces no triple.
	expanded, err := ld.NewJsonLdProcessor().Expand(rooted, NewJSONLDOptions(""))
	require.NoError(t, err)
	encoded, err := json.Marshal(expanded)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "vocab#note",
		"a reset context must not leave the node inheriting definitions")
}

// TestRootCompactedDocumentKeepsExistingIncluded: the promoted root may
// already carry @included entries. Replacing them with the former graph
// siblings dropped those nodes - and they sit in the same graph, so dropping
// them removes their triples from the dataset this is supposed to carry
// through unchanged.
func TestRootCompactedDocumentKeepsExistingIncluded(t *testing.T) {
	rooted, err := RootCompactedDocument(map[string]any{
		"@context": map[string]any{"id": "@id", "note": "https://example.org/vocab#note"},
		"@graph": []any{
			map[string]any{"id": "https://example.org/sibling", "note": "a former graph sibling"},
			map[string]any{
				"id":        "https://example.org/credential",
				"note":      "the root",
				"@included": []any{map[string]any{"id": "https://example.org/already", "note": "carried by the root"}},
			},
		},
	}, "https://example.org/credential", nil)
	require.NoError(t, err)

	included, isList := rooted["@included"].([]any)
	require.True(t, isList)
	require.Len(t, included, 2, "the root's own @included and the former sibling")

	var ids []string
	for _, entry := range included {
		id, _ := entry.(map[string]any)["id"].(string)
		ids = append(ids, id)
	}
	require.Contains(t, ids, "https://example.org/already", "what the root already included stays")
	require.Contains(t, ids, "https://example.org/sibling", "and the sibling joins it")

	// The triples are the point: both nodes must still be in the dataset.
	expanded, err := ld.NewJsonLdProcessor().Expand(rooted, NewJSONLDOptions(""))
	require.NoError(t, err)
	encoded, err := json.Marshal(expanded)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "carried by the root")
	require.Contains(t, string(encoded), "a former graph sibling")
}

// TestProofKeysHonoursExpandContext: RootProofs expands the document under the
// credential's options, ExpandContext included. Resolving member names without
// it made selection disagree with the expansion it is meant to match, so an
// external context aliasing "proof" had signing and SD proof removal act on a
// different member than the one carrying the proof.
func TestProofKeysHonoursExpandContext(t *testing.T) {
	var external any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"@context":{"seal":"https://w3id.org/security#proof"}}`), &external))

	options := NewJSONLDOptions("")
	options.ExpandContext = external

	node := map[string]any{
		"id":   "https://example.org/credential",
		"seal": map[string]any{"type": "DataIntegrityProof"},
	}

	require.Equal(t, []string{"seal"}, ProofKeys(node, nil, options),
		"an alias from the expand context names the proof")

	// Without it, the same document resolves nothing - which is the
	// disagreement this closes.
	require.Empty(t, ProofKeys(node, nil, NewJSONLDOptions("")))
}

// TestRootCompactedDocumentKeepsSiblingContextScope: inside @graph, every node
// saw the CONTAINER's context and its own. Moving the siblings under the
// promoted root put them inside that root's local context too - so a term the
// root redefines changed the sibling's expanded IRI, and with it the RDF and
// any signature over it. In a helper whose entire promise is that the dataset
// comes through unchanged.
func TestRootCompactedDocumentKeepsSiblingContextScope(t *testing.T) {
	container := map[string]any{
		"id":      "@id",
		"note":    "https://example.org/vocab#note",
		"carries": map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
	}

	document := map[string]any{
		"@context": container,
		"@graph": []any{
			map[string]any{
				// The root redefines the very term its sibling uses.
				"@context": map[string]any{"note": "https://example.org/OVERRIDDEN#note"},
				"id":       "https://example.org/credential",
				"carries":  "https://example.org/other",
			},
			map[string]any{"id": "https://example.org/other", "note": "written under the container's context"},
		},
	}

	before, err := canonicalFormOf(document, nil)
	require.NoError(t, err)
	require.Contains(t, before, "https://example.org/vocab#note",
		"the sibling's note is the container's term before rooting")

	rooted, err := RootCompactedDocument(document, "", nil)
	require.NoError(t, err)
	require.Equal(t, "https://example.org/credential", rooted["id"])

	after, err := canonicalFormOf(rooted, nil)
	require.NoError(t, err)
	require.Equal(t, before, after,
		"rooting a document must not change one quad of it")
	require.NotContains(t, after, "OVERRIDDEN",
		"the root's own context does not reach the nodes that were beside it")
}

// TestRootCompactedDocumentFallsBackWhenTheResetIsRefused: the scope is
// restored with a leading null, and JSON-LD REFUSES to nullify a context
// holding @protected terms. That is why the unscoped form is tried second -
// here the root's own context only ADDS a term, so nothing the sibling uses
// moves and the document comes through unchanged.
func TestRootCompactedDocumentFallsBackWhenTheResetIsRefused(t *testing.T) {
	container := map[string]any{
		"@protected": true,
		"id":         "@id",
		"note":       "https://example.org/vocab#note",
		"carries":    map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
	}

	document := map[string]any{
		"@context": container,
		"@graph": []any{
			map[string]any{
				"@context": map[string]any{"extra": "https://example.org/vocab#extra"},
				"id":       "https://example.org/credential",
				"carries":  "https://example.org/other",
				"extra":    "only the root uses this",
			},
			map[string]any{"id": "https://example.org/other", "note": "unchanged"},
		},
	}

	before, err := canonicalFormOf(document, nil)
	require.NoError(t, err)

	rooted, err := RootCompactedDocument(document, "", nil)
	require.NoError(t, err, "a protected container context must not make a document unrootable")

	after, err := canonicalFormOf(rooted, nil)
	require.NoError(t, err)
	require.Equal(t, before, after, "and the dataset still comes through unchanged")
}

// TestRootCompactedDocumentRefusesWhenTheDatasetWouldChange: neither form
// works when the container's context is @protected - so the scope cannot be
// restored - AND the root's own context defines a term a sibling uses, which
// the container left undefined and expansion therefore dropped. Promoting the
// root would mint a triple the signed document never carried. The helper says
// no rather than returning a document about a different graph.
func TestRootCompactedDocumentRefusesWhenTheDatasetWouldChange(t *testing.T) {
	document := map[string]any{
		"@context": map[string]any{
			"@protected": true,
			"id":         "@id",
			"carries":    map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
		},
		"@graph": []any{
			map[string]any{
				"@context": map[string]any{"note": "https://example.org/vocab#note"},
				"id":       "https://example.org/credential",
				"carries":  "https://example.org/other",
			},
			// "note" is undefined in the container, so this says nothing at
			// all until the root's context reaches it.
			map[string]any{"id": "https://example.org/other", "note": "a triple that does not exist yet"},
		},
	}

	_, err := RootCompactedDocument(document, "", nil)
	require.Error(t, err, "rooting must not invent a triple")
	require.Contains(t, err.Error(), "would change its RDF")
}

// splitFragmentDocument: one node written as TWO @graph entries, which is a
// shape flattening produces. The document is unambiguous - it has exactly one
// node nothing refers to - but reading each entry as a node of its own made it
// look like two.
func splitFragmentDocument() map[string]any {
	return map[string]any{
		"@context": map[string]any{
			"id":      "@id",
			"note":    "https://example.org/vocab#note",
			"carries": map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
		},
		"@graph": []any{
			map[string]any{"id": "https://example.org/credential", "carries": "https://example.org/other"},
			map[string]any{"id": "https://example.org/credential", "note": "the second fragment"},
			map[string]any{"id": "https://example.org/other", "note": "a sibling"},
		},
	}
}

// TestRootCompactedDocumentMergesSplitFragments: the fragments are one node,
// so the document says exactly which node it is about. Reading them as two
// refused it for holding "more than one node nothing refers to" - and the
// promoted root would otherwise carry only whichever fragment came first.
func TestRootCompactedDocumentMergesSplitFragments(t *testing.T) {
	before, err := canonicalFormOf(splitFragmentDocument(), nil)
	require.NoError(t, err)

	rooted, err := RootCompactedDocument(splitFragmentDocument(), "", nil)
	require.NoError(t, err, "fragments of one node do not make a document ambiguous")
	require.Equal(t, "https://example.org/credential", rooted["id"])
	require.Equal(t, "https://example.org/other", rooted["carries"],
		"the promoted root carries the first fragment's properties")
	require.Equal(t, "the second fragment", rooted["note"],
		"and the second fragment's too, rather than whichever came first")

	after, err := canonicalFormOf(rooted, nil)
	require.NoError(t, err)
	require.Equal(t, before, after, "merging fragments must not change one quad")
}

// TestRootCompactedDocumentRefusesUnderJSONLD10: @included is a JSON-LD 1.1
// keyword and 1.1 ONLY. A 1.0 processor treats it as an unknown term and skips
// it, so every sibling moved there - and every triple it carries - vanishes.
// The hash would be taken over less than the document says, while a verifier
// reading the same bytes under 1.1 defaults sees those triples reappear.
func TestRootCompactedDocumentRefusesUnderJSONLD10(t *testing.T) {
	options := NewJSONLDOptions("")
	options.ProcessingMode = ld.JsonLd_1_0

	document := map[string]any{
		"@context": map[string]any{
			"id":      "@id",
			"note":    "https://example.org/vocab#note",
			"carries": map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
		},
		"@graph": []any{
			map[string]any{"id": "https://example.org/credential", "carries": "https://example.org/other"},
			map[string]any{"id": "https://example.org/other", "note": "a sibling that must survive"},
		},
	}

	_, err := RootCompactedDocument(document, "", options)
	require.Error(t, err)
	require.Contains(t, err.Error(), "JSON-LD 1.0")

	// A single node needs no @included, so 1.0 is no obstacle to rooting it.
	single := map[string]any{
		"@context": map[string]any{"id": "@id", "note": "https://example.org/vocab#note"},
		"@graph":   []any{map[string]any{"id": "https://example.org/credential", "note": "alone"}},
	}
	rooted, err := RootCompactedDocument(single, "", options)
	require.NoError(t, err, "nothing moves, so nothing is lost")
	require.Equal(t, "https://example.org/credential", rooted["id"])
}
