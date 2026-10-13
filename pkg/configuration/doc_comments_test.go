package configuration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every documented declaration in this package must be documented by a
// comment that names it.
func TestDocCommentsDescribeTheirOwnDeclaration(t *testing.T) {
	docCommentNames(t, nil)
}

// docCommentNames reports declarations whose doc comment does not start
// with their own name.
//
// The rule is ordinary Go style, but the reason for enforcing it here is
// specific: inserting a declaration directly above an existing one steals
// that one's doc comment, and the result compiles, passes every test, and
// is invisible in a diff - the moved lines show as unchanged context. It
// surfaces as generated documentation describing the wrong thing, which
// is to say it usually does not surface at all.
//
// I made exactly this mistake twice in this feature: once displacing
// BBSConfig's explanation onto a constant block, once displacing
// checkCredentialMetadataEntries' onto checkCommitmentTargets. A guard
// that derives the set of declarations itself is the only kind that would
// have caught the second after the first.
func docCommentNames(t *testing.T, exempt map[string]string) {
	t.Helper()

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ParseComments)
		require.NoError(t, err)

		for _, decl := range file.Decls {
			for ident, doc := range declDocs(decl) {
				if doc == nil || len(doc.List) == 0 {
					continue
				}
				if why, ok := exempt[ident]; ok {
					t.Logf("exempt: %s (%s)", ident, why)
					continue
				}
				checked++
				first := strings.TrimPrefix(doc.List[0].Text, "//")
				first = strings.TrimSpace(first)
				assert.True(t, first == ident || strings.HasPrefix(first, ident+" ") || strings.HasPrefix(first, ident+","),
					"%s: the doc comment above it begins %q - either it documents something else, "+
						"or a declaration was inserted between a comment and the thing it describes",
					ident, truncate(first))
			}
		}
	}
	require.NotZero(t, checked, "no documented declarations found; this guard would pass vacuously")
}

// declDocs maps each documented top-level declaration to its comment.
func declDocs(decl ast.Decl) map[string]*ast.CommentGroup {
	out := map[string]*ast.CommentGroup{}
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil {
			out[d.Name.Name] = d.Doc
		}
	case *ast.GenDecl:
		// A parenthesised block's own comment documents the group, not any
		// one name, so only a single-spec declaration is checked.
		if d.Lparen.IsValid() || len(d.Specs) != 1 {
			return out
		}
		switch spec := d.Specs[0].(type) {
		case *ast.TypeSpec:
			out[spec.Name.Name] = d.Doc
		case *ast.ValueSpec:
			if len(spec.Names) == 1 {
				out[spec.Names[0].Name] = d.Doc
			}
		}
	}
	return out
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
