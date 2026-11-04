package credential

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/credential/primitives"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A derivation reads a claim as presented after an earlier one copied the
// claim's object and changed the copy.
func TestApplyDerivations_CopyLeavesItsSourceUnchanged(t *testing.T) {
	out, err := ApplyDerivations([]primitives.Derivation{
		{Copy: &primitives.CopyArgs{Input: "identity", Output: "alias"}},
		{Lowercase: &primitives.LowercaseArgs{Input: "alias.name"}},
		{Copy: &primitives.CopyArgs{Input: "identity.name", Output: "seen"}},
	}, map[string]any{"identity": map[string]any{"name": "ALICE"}}, time.Now())
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"name": "alice"}, out["alias"])
	assert.Equal(t, "ALICE", out["seen"])
}

// A copy replaces an object already at its output path, in the pipeline and
// in the document the output is merged into.
func TestCopyReplacesAnExistingObject(t *testing.T) {
	list := []primitives.Derivation{
		{Copy: &primitives.CopyArgs{Input: "identity", Output: "alias"}},
		{Copy: &primitives.CopyArgs{Input: "identity.name", Output: "nested.alias_name"}},
	}
	claims := map[string]any{
		"identity": map[string]any{"name": "ALICE"},
		"alias":    map[string]any{"obsolete": "retained"},
		"nested":   map[string]any{"other": "kept", "alias_name": "old"},
	}

	out, err := ApplyDerivations(list, claims, time.Now())
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"name": "ALICE"}, out["alias"])

	doc := CloneNestedClaims(claims)
	MergeDerived(doc, out, list)
	assert.Equal(t, map[string]any{"name": "ALICE"}, doc["alias"], "the obsolete field is gone")
	assert.Equal(t, map[string]any{"other": "kept", "alias_name": "ALICE"}, doc["nested"], "siblings of a leaf copy stay")
}
