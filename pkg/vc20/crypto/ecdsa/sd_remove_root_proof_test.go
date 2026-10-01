package ecdsa

import (
	"encoding/json"
	"testing"

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
	// carries, side by side, linked only by an id reference.
	flattened := []any{
		map[string]any{
			"id":                "https://example.org/credentials/outer",
			"type":              "VerifiableCredential",
			"credentialSubject": "https://example.org/credentials/inner",
			"proof":             map[string]any{"type": "DataIntegrityProof", "proofValue": "outer"},
		},
		map[string]any{
			"id":    "https://example.org/credentials/inner",
			"type":  "VerifiableCredential",
			"proof": map[string]any{"type": "DataIntegrityProof", "proofValue": "inner"},
		},
	}

	require.NoError(t, removeRootProof(flattened))

	outer := flattened[0].(map[string]any)
	inner := flattened[1].(map[string]any)
	require.NotContains(t, outer, "proof", "the document's own proof is what gets removed")
	require.Contains(t, inner, "proof",
		"the carried credential's proof is content the outer signature covers")
}

// A flattened document that does not say which node it is about is refused
// rather than half-stripped.
func TestRemoveRootProofRefusesAnAmbiguousDocument(t *testing.T) {
	t.Run("two unreferenced nodes", func(t *testing.T) {
		document := []any{
			map[string]any{"id": "https://example.org/a", "proof": map[string]any{}},
			map[string]any{"id": "https://example.org/b", "proof": map[string]any{}},
		}
		err := removeRootProof(document)
		require.ErrorContains(t, err, "more than one node nothing refers to")
		require.Contains(t, document[0].(map[string]any), "proof", "nothing is removed on a refusal")
		require.Contains(t, document[1].(map[string]any), "proof")
	})

	t.Run("a reference cycle", func(t *testing.T) {
		document := []any{
			map[string]any{"id": "https://example.org/a", "rel": "https://example.org/b"},
			map[string]any{"id": "https://example.org/b", "rel": "https://example.org/a"},
		}
		require.ErrorContains(t, removeRootProof(document), "referred to by another")
	})
}

// A single node is the document, under either spelling of its proof link.
func TestRemoveRootProofHandlesASingleNode(t *testing.T) {
	var document any
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "https://example.org/credentials/outer",
		"https://w3id.org/security#proof": {"type": "DataIntegrityProof"},
		"credentialSubject": {"proof": {"type": "DataIntegrityProof"}}
	}`), &document))

	require.NoError(t, removeRootProof(document))

	node := document.(map[string]any)
	require.NotContains(t, node, "https://w3id.org/security#proof")
	require.Contains(t, node["credentialSubject"].(map[string]any), "proof",
		"a nested proof is never the document's own")
}
