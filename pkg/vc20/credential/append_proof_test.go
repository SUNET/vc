package credential

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAppendProofDropsANullProof: "proof": null is a term REMOVAL in JSON-LD,
// so a document carrying one carries no proof. Treating it as an existing
// proof to keep alongside the new one wrote "proof": [null, {...}] into every
// document signed from that shape - it verified here, since expansion drops
// the null, but it is not a document another implementation has to accept.
func TestAppendProofDropsANullProof(t *testing.T) {
	proof := map[string]any{"type": "DataIntegrityProof"}

	t.Run("an explicit null", func(t *testing.T) {
		doc := map[string]any{"proof": nil}
		AppendProof(doc, proof)
		require.Equal(t, proof, doc["proof"],
			"a null proof is no proof, so the new one stands alone")
	})

	t.Run("a null inside a proof set", func(t *testing.T) {
		existing := map[string]any{"type": "DataIntegrityProof", "created": "2020-01-01T00:00:00Z"}
		doc := map[string]any{"proof": []any{nil, existing, nil}}
		AppendProof(doc, proof)
		require.Equal(t, []any{existing, proof}, doc["proof"],
			"the real proof is kept and the nulls are not")
	})

	t.Run("a real proof is still kept", func(t *testing.T) {
		existing := map[string]any{"type": "DataIntegrityProof", "created": "2020-01-01T00:00:00Z"}
		doc := map[string]any{"proof": existing}
		AppendProof(doc, proof)
		require.Equal(t, []any{existing, proof}, doc["proof"],
			"signing twice makes a proof SET, not a replacement")
	})

	t.Run("no proof at all", func(t *testing.T) {
		doc := map[string]any{}
		AppendProof(doc, proof)
		require.Equal(t, proof, doc["proof"])
	})
}
