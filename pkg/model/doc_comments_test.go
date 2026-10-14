package model

import (
	"testing"

	"github.com/SUNET/vc/internal/docguard"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every documented declaration in this package must be documented by a
// comment that names it. See package docguard for why this is worth a
// guard rather than care: the failure compiles, passes, and is invisible
// in a diff.
func TestDocCommentsDescribeTheirOwnDeclaration(t *testing.T) {
	findings, checked, err := docguard.Check(".", map[string]string{
		// Pre-existing on main: the type was renamed from OIDCConfig and
		// the comment was not. A stale comment, not a displaced one, and
		// not this PR's to sweep in.
		"OIDCOP": "comment carries the type's former name",
	})
	require.NoError(t, err)
	require.NotZero(t, checked, "nothing was examined; this guard would pass vacuously")

	for _, f := range findings {
		assert.Fail(t, f.String())
	}
}
