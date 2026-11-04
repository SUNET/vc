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

	out, replaced, err := ApplyDerivationsReplacing(list, claims, time.Now(), nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"name": "ALICE"}, out["alias"])

	doc := CloneNestedClaims(claims)
	MergeDerived(doc, out, replaced)
	assert.Equal(t, map[string]any{"name": "ALICE"}, doc["alias"], "the obsolete field is gone")
	assert.Equal(t, map[string]any{"other": "kept", "alias_name": "ALICE"}, doc["nested"], "siblings of a leaf copy stay")
}

// A copy whose input is absent writes nothing, so it clears nothing, even
// when a later step writes under its output path.
func TestASkippedCopyClearsNothing(t *testing.T) {
	list := []primitives.Derivation{
		{Copy: &primitives.CopyArgs{Input: "missing", Output: "identity"}},
		{Lowercase: &primitives.LowercaseArgs{Input: "identity.name"}},
	}
	claims := map[string]any{"identity": map[string]any{"name": "ALICE", "country": "SE"}}

	out, replaced, err := ApplyDerivationsReplacing(list, claims, time.Now(), nil)
	require.NoError(t, err)
	assert.Empty(t, replaced, "the copy wrote nothing")

	doc := CloneNestedClaims(claims)
	MergeDerived(doc, out, replaced)
	assert.Equal(t, map[string]any{"name": "alice", "country": "SE"}, doc["identity"])
}
