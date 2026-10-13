package apiv1

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

// Every signing path must inject commitments.
//
// This is a position guard rather than a behavioural test because the
// failure it catches is an ABSENCE: a scope configures a commitment
// claim, startup accepts it, and the credential is signed without the
// claim. Nothing fails, nobody is told, and the credential is wrong in a
// way that only surfaces when a wallet tries to prove with it.
//
// It was absent twice already - MakeVC20 and MakeJWP both signed
// req.DocumentData unchanged while the feature advertised support for any
// credential type. A new signing path added later would make the same
// omission, and no test written against today's handlers would notice.
func TestEverySigningPathInjectsCommitments(t *testing.T) {
	const (
		marker = "injectCommitments"
		// The status list entry is allocated before signing and never
		// handed back, so anything that can REFUSE a document has to run
		// before it or every refusal burns a revocation entry.
		allocMarker = "TokenStatusListAddStatus"
	)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	// A signing path is a method on *Client whose request carries
	// document_data: that is the document about to be signed, so it is
	// exactly the set that has to inject.
	found := map[string]bool{}
	order := map[string]bool{}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		require.NoError(t, err)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Make") {
				continue
			}
			if !takesDocumentData(fn, file) {
				continue
			}

			injectPos, allocPos := token.NoPos, token.NoPos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case marker:
					if !injectPos.IsValid() {
						injectPos = sel.Pos()
					}
				case allocMarker:
					if !allocPos.IsValid() {
						allocPos = sel.Pos()
					}
				}
				return true
			})
			found[fn.Name.Name] = injectPos.IsValid()
			if injectPos.IsValid() && allocPos.IsValid() {
				order[fn.Name.Name] = injectPos < allocPos
			}
		}
	}

	require.NotEmpty(t, found, "no signing paths found; this guard would pass vacuously")
	for _, want := range []string{"MakeSDJWT", "MakeMDoc", "MakeVC20", "MakeJWP"} {
		assert.Contains(t, found, want, "%s should have been recognised as a signing path", want)
	}

	for name, calls := range found {
		assert.True(t, calls,
			"%s signs a document but never calls %s: a scope configuring a commitment claim "+
				"would be issued without it, silently", name, marker)
	}

	// Injection can refuse a document, and a refusal after the allocation
	// leaves a VALID revocation entry belonging to no credential.
	require.NotEmpty(t, order, "no handler allocates a status entry; the ordering guard would pass vacuously")
	for name, injectFirst := range order {
		assert.True(t, injectFirst,
			"%s calls %s AFTER %s: every refused issuance would burn a revocation entry",
			name, marker, allocMarker)
	}
}

// takesDocumentData reports whether fn's request parameter type declares a
// DocumentData field - which is what makes it a signing path rather than,
// say, a metadata call.
func takesDocumentData(fn *ast.FuncDecl, file *ast.File) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, param := range fn.Type.Params.List {
		star, ok := param.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if !ok {
			continue
		}
		if structHasField(file, ident.Name, "DocumentData") {
			return true
		}
	}
	return false
}

func structHasField(file *ast.File, typeName, fieldName string) bool {
	has := false
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != typeName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, f := range st.Fields.List {
			for _, nm := range f.Names {
				if nm.Name == fieldName {
					has = true
				}
			}
		}
		return false
	})
	return has
}
