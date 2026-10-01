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
	require.ErrorContains(t, err, "rather than one proof")
}
