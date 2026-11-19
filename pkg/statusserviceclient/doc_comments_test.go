package statusserviceclient

import (
	"testing"

	"github.com/SUNET/vc/internal/docguard"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every documented declaration in this package must be documented by a
// comment that names it. See package docguard for why this is worth a guard
// rather than care: the failure compiles, passes, and is invisible in a diff.
//
// It caught one here on the way in - classifyStatus's comment had been
// orphaned above classifyResourceStatus by a declaration inserted between
// them, so the file documented the wrong function and left the other with
// nothing.
func TestDocCommentsDescribeTheirOwnDeclaration(t *testing.T) {
	findings, checked, err := docguard.Check(".", nil)
	require.NoError(t, err)
	require.NotZero(t, checked, "nothing was examined; this guard would pass vacuously")

	for _, f := range findings {
		assert.Fail(t, f.String())
	}
}
