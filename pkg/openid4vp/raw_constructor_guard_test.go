package openid4vp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Writing CredentialQuery{Raw: ...} by hand compiles and is wrong.
//
// Raw is authoritative for the WIRE and nothing else, and plenty of this
// stack reads the struct: UIInteraction records ID in the authorization
// context's scopes and the response path matches a presentation back to
// it; matching reads Meta.TypeValues; Multiple and
// RequireCryptographicHolderBinding decide what a response may contain. A
// hand-built raw query is therefore sent correctly and then tracked under
// defaults nobody chose - which surfaces as a result that cannot be
// matched, with nothing malformed to point at.
//
// NewRawCredentialQuery fills the shadow in. "Callers should use the
// constructor" is advice, and advice does not survive the next caller, so
// this makes it a rule: production code may not write the literal.
//
// Tests may, and do - asserting what a hand-built query does IS the
// subject of some of them.
func TestRawIsOnlyConstructedThroughTheConstructor(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	// Where the shadow is actually populated, and so the only file that
	// may build the literal.
	sanctioned := filepath.Join(root, "pkg", "openid4vp", "dcql.go")

	fset := token.NewFileSet()
	var inspected, literals int
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "vendor", ".git", "node_modules", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == sanctioned {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil // not ours to police
		}
		inspected++
		ast.Inspect(file, func(n ast.Node) bool {
			composite, ok := n.(*ast.CompositeLit)
			if !ok || !isCredentialQueryType(composite.Type) {
				return true
			}
			for _, element := range composite.Elts {
				kv, ok := element.(*ast.KeyValueExpr)
				if !ok {
					// An UNKEYED literal sets fields by position, so it
					// can reach Raw without ever naming it - and skipping
					// those, as this did at first, left the invariant
					// open to the one spelling nobody reads carefully.
					//
					// Rejected wholesale rather than counted to Raw's
					// position: that position changes whenever a field is
					// added, which would make this guard quietly stop
					// looking at the right thing.
					literals++
					t.Errorf("%s: a CredentialQuery literal must name its fields - "+
						"an unkeyed one can set Raw by position, and a raw query not built by "+
						"openid4vp.NewRawCredentialQuery carries no ID, Format or Meta, so the "+
						"response path cannot match it",
						fset.Position(element.Pos()))
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Raw" {
					literals++
					t.Errorf("%s: build a raw query with openid4vp.NewRawCredentialQuery, not a literal - "+
						"a hand-built one carries no ID, Format or Meta, and the response path cannot match it",
						fset.Position(kv.Pos()))
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)

	// Fail closed: a walk that inspected nothing proves nothing.
	require.NotZerof(t, inspected, "walked %s and parsed no Go files; this guard is not looking at anything", root)
	require.Zero(t, literals)
}

func isCredentialQueryType(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident: // within this package
		return typed.Name == "CredentialQuery"
	case *ast.SelectorExpr: // openid4vp.CredentialQuery
		return typed.Sel.Name == "CredentialQuery"
	}
	return false
}
