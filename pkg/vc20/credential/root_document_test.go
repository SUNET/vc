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
