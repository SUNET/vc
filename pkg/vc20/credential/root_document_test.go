package credential

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootCompactedDocument(t *testing.T) {
	t.Run("a single node is already rooted", func(t *testing.T) {
		document := map[string]any{"id": "https://example.org/a", "proof": map[string]any{}}
		rooted, err := RootCompactedDocument(document, "")
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
		}, "https://example.org/credential")
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
		}, "")
		require.NoError(t, err)
		require.Equal(t, "https://example.org/credential", rooted["id"])
	})

	t.Run("a known root that is gone is refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@graph": []any{map[string]any{"id": "https://example.org/subject"}},
		}, "https://example.org/credential")
		require.ErrorContains(t, err, "no longer holds the node")

		// And the same when disclosure left exactly one node behind, so the
		// document is not a container at all.
		_, err = RootCompactedDocument(map[string]any{
			"id": "https://example.org/subject",
		}, "https://example.org/credential")
		require.ErrorContains(t, err, "no longer holds the node")
	})

	t.Run("an ambiguous document is refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@graph": []any{
				map[string]any{"id": "https://example.org/a"},
				map[string]any{"id": "https://example.org/b"},
			},
		}, "")
		require.ErrorContains(t, err, "more than one node nothing refers to")
	})

	t.Run("a context on the node survives when the container has none", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@graph": []any{
				map[string]any{"@context": "https://www.w3.org/ns/credentials/v2", "id": "https://example.org/credential"},
			},
		}, "")
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
	}, "")
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
		}, "https://example.org/credentials/outer")
		require.NoError(t, err, "a compact spelling names the same node")
		require.Equal(t, "ex:outer", rooted["@id"])
	})

	t.Run("as a single node", func(t *testing.T) {
		rooted, err := RootCompactedDocument(map[string]any{
			"@context": context,
			"@id":      "ex:outer",
		}, "https://example.org/credentials/outer")
		require.NoError(t, err)
		require.Equal(t, "ex:outer", rooted["@id"])
	})

	t.Run("a genuinely different node is still refused", func(t *testing.T) {
		_, err := RootCompactedDocument(map[string]any{
			"@context": context,
			"@id":      "ex:someone-else",
		}, "https://example.org/credentials/outer")
		require.ErrorContains(t, err, "no longer holds the node")
	})
}
