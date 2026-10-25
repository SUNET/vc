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
