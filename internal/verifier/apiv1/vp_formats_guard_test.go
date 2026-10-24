package apiv1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// vp_formats_supported is REQUIRED in client_metadata whenever the wallet
// cannot learn it another way (OpenID4VP 1.0 11.1), and
// verifier.preferred_vp_formats has no default - so reading the config
// field directly sends nothing at all on a deployment that never set it.
// That is exactly the bug vpFormatsOrDefault exists to have fixed, and it
// is invisible: the request object is well-formed, just missing a member,
// and only a conformant wallet complains.
//
// A new construction site is how it comes back, so the guard walks the
// package rather than naming the two sites that exist today - an
// enumeration would go stale the moment a third one is written, which is
// the moment it is needed.
func TestEveryVPFormatsAssignmentGoesThroughTheDefault(t *testing.T) {
	const helper = "vpFormatsOrDefault"

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	var checked int
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			// ClientMetadata{VPFormatsSupported: ...}
			case *ast.CompositeLit:
				for _, element := range node.Elts {
					kv, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "VPFormatsSupported" {
						checked++
						assertCallsHelper(t, fset, kv.Value, helper)
					}
				}
			// something.ClientMetadata.VPFormatsSupported = ...
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "VPFormatsSupported" || i >= len(node.Rhs) {
						continue
					}
					checked++
					assertCallsHelper(t, fset, node.Rhs[i], helper)
				}
			}
			return true
		})
	}

	// Fail closed. Zero sites means the walk found nothing - a renamed
	// field, a moved package, a parser that silently skipped everything -
	// and a guard that passes because it looked at nothing is worse than
	// none, since it reports safety it never established.
	require.NotZero(t, checked, "found no vp_formats_supported assignment to check; the guard is not looking at anything")
}

func assertCallsHelper(t *testing.T, fset *token.FileSet, value ast.Expr, helper string) {
	t.Helper()
	where := filepath.Base(fset.Position(value.Pos()).String())
	call, ok := value.(*ast.CallExpr)
	require.Truef(t, ok, "%s: vp_formats_supported must come from %s(), not a direct read", where, helper)
	ident, ok := call.Fun.(*ast.Ident)
	require.Truef(t, ok && ident.Name == helper, "%s: vp_formats_supported must come from %s()", where, helper)
}
