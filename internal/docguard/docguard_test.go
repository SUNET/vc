package docguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// write puts one Go file in a fresh directory and checks it.
func check(t *testing.T, src string, exempt map[string]string) ([]Finding, int) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	findings, checked, err := Check(dir, exempt)
	require.NoError(t, err)
	return findings, checked
}

// The motivating case, and the one the first version of this guard missed:
// a parenthesised group inserted between a type and its explanation. The
// group is not a single declaration, and the type below it is left
// undocumented, so a position-based check sees nothing wrong.
func TestAGroupCarryingAnotherDeclarationsComment(t *testing.T) {
	findings, checked := check(t, `package x

// Config holds the thing.
const (
	A = 1
	B = 2
)

type Config struct{}
`, nil)
	require.NotZero(t, checked)
	require.Len(t, findings, 1)
	assert.Equal(t, "Config", findings[0].Names)
	assert.Empty(t, findings[0].Declaration, "a group belongs to no single name")
	assert.Contains(t, findings[0].String(), "inserted between that comment and its declaration")
}

// The same displacement between two single declarations.
func TestADeclarationCarryingAnothersComment(t *testing.T) {
	findings, _ := check(t, `package x

// Original does the original thing.
func Inserted() {}

func Original() {}
`, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "Inserted", findings[0].Declaration)
	assert.Equal(t, "Original", findings[0].Names)
}

func TestWellFormedCommentsPass(t *testing.T) {
	findings, checked := check(t, `package x

// Config holds the thing.
type Config struct{}

// Numbers are some numbers.
const (
	A = 1
	B = 2
)

// Do does the thing.
func Do() {}

// Method comments are not checked, since a method name is not unique.
func (c Config) Do() {}
`, nil)
	assert.Empty(t, findings)
	assert.NotZero(t, checked)
}

// A group comment that names nothing in the package is a prose heading,
// not a displaced comment.
func TestAGroupCommentNamingNothingIsFine(t *testing.T) {
	findings, _ := check(t, `package x

// Numbers used by the parser.
const (
	A = 1
	B = 2
)
`, nil)
	assert.Empty(t, findings)
}

func TestExemptionsAreHonoured(t *testing.T) {
	src := `package x

// FormerName holds the thing.
type Renamed struct{}
`
	findings, _ := check(t, src, nil)
	require.Len(t, findings, 1, "guard: without the exemption this is a finding")

	findings, _ = check(t, src, map[string]string{"Renamed": "comment carries the type's former name"})
	assert.Empty(t, findings)
}

// Test files are skipped: a guard that flagged its own fixtures would be
// unusable in the package it guards.
func TestTestFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(`package x

// Config holds the thing.
func Inserted() {}

type Config struct{}
`), 0o600))
	findings, checked, err := Check(dir, nil)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Zero(t, checked)
}
