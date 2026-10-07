package common

import "testing"

// CountProofNodes exists so a caller that names no proof can have its
// implicit claim - "this document has exactly one" - checked rather than
// assumed. Verify used to take the first node the traversal reached, which
// for a presentation could be the embedded credential's issuer proof
// instead of the holder's.
func TestCountProofNodes(t *testing.T) {
	proof := func(value string) map[string]any {
		return map[string]any{"type": "DataIntegrityProof", "proofValue": value}
	}

	for name, tc := range map[string]struct {
		doc  any
		want int
	}{
		"no proof at all":   {map[string]any{"id": "urn:x"}, 0},
		"one proof":         {map[string]any{"proof": proof("z1")}, 1},
		"two side by side":  {map[string]any{"proof": []any{proof("z1"), proof("z2")}}, 2},
		"nested in a graph": {map[string]any{"proof": proof("z1"), "verifiableCredential": map[string]any{"proof": proof("z2")}}, 2},
		"nil":               {nil, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := CountProofNodes(tc.doc, "DataIntegrityProof"); got != tc.want {
				t.Fatalf("CountProofNodes = %d, want %d", got, tc.want)
			}
		})
	}

	// The presentation shape is the one that matters: the holder's proof
	// and the embedded credential's issuer proof, which is exactly the
	// ambiguity Verify must refuse rather than resolve.
	t.Run("a presentation carrying an embedded credential", func(t *testing.T) {
		vp := map[string]any{
			"type":  "VerifiablePresentation",
			"proof": proof("holder-signature"),
			"verifiableCredential": []any{map[string]any{
				"type":  "VerifiableCredential",
				"proof": proof("issuer-signature"),
			}},
		}
		if got := CountProofNodes(vp, "DataIntegrityProof"); got != 2 {
			t.Fatalf("a presentation with one embedded credential holds 2 proofs, got %d", got)
		}
	})
}
