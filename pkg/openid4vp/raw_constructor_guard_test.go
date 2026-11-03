package openid4vp

import (
	"fmt"
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
	var inspected int
	var violations []string
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
		violations = append(violations, rawQueryLiteralViolations(fset, file)...)
		return nil
	})
	require.NoError(t, err)

	// Fail closed: a walk that inspected nothing proves nothing.
	require.NotZerof(t, inspected, "walked %s and parsed no Go files; this guard is not looking at anything", root)
	require.Empty(t, violations, strings.Join(violations, "\n"))
}

// rawQueryLiteralViolations reports every CredentialQuery literal in file
// that builds Raw by hand, or that could reach Raw by position.
//
// The subtlety is that an element of a slice, array or map OMITS its type:
// in []CredentialQuery{{Raw: raw}} the inner CompositeLit has Type == nil,
// so asking it what type it builds returns nothing and the literal sails
// past. The enclosing literal is the only thing that knows, and ast.Inspect
// walks parents before children, so each literal records the element type
// its children will be missing before those children are visited.
func rawQueryLiteralViolations(fset *token.FileSet, file *ast.File) []string {
	var found []string
	elided := map[*ast.CompositeLit]ast.Expr{}

	ast.Inspect(file, func(n ast.Node) bool {
		composite, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typ := composite.Type
		if typ == nil {
			typ = elided[composite]
		}

		keyType, valueType := compositeElementTypes(typ)
		for _, element := range composite.Elts {
			if kv, ok := element.(*ast.KeyValueExpr); ok {
				noteElidedType(elided, kv.Key, keyType)
				noteElidedType(elided, kv.Value, valueType)
				continue
			}
			noteElidedType(elided, element, valueType)
		}

		if !isCredentialQueryType(typ) {
			// A literal whose type we could not resolve and which names
			// Raw is reported anyway rather than waved through: resolving
			// a struct FIELD's elided type needs go/types, and a guard
			// that cannot tell must refuse, not assume.
			if typ == nil {
				for _, element := range composite.Elts {
					kv, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Raw" {
						found = append(found, fmt.Sprintf(
							"%s: this literal sets Raw but omits its type, so the guard cannot tell "+
								"whether it is a CredentialQuery - name the type explicitly, and build raw "+
								"queries with openid4vp.NewRawCredentialQuery",
							fset.Position(kv.Pos())))
					}
				}
			}
			return true
		}

		for _, element := range composite.Elts {
			kv, ok := element.(*ast.KeyValueExpr)
			if !ok {
				// An UNKEYED literal sets fields by position, so it can
				// reach Raw without ever naming it - and skipping those,
				// as this did at first, left the invariant open to the one
				// spelling nobody reads carefully.
				//
				// Rejected wholesale rather than counted to Raw's
				// position: that position changes whenever a field is
				// added, which would make this guard quietly stop looking
				// at the right thing.
				found = append(found, fmt.Sprintf(
					"%s: a CredentialQuery literal must name its fields - an unkeyed one can set "+
						"Raw by position, and a raw query not built by openid4vp.NewRawCredentialQuery "+
						"carries no ID, Format or Meta, so the response path cannot match it",
					fset.Position(element.Pos())))
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Raw" {
				found = append(found, fmt.Sprintf(
					"%s: build a raw query with openid4vp.NewRawCredentialQuery, not a literal - "+
						"a hand-built one carries no ID, Format or Meta, and the response path cannot match it",
					fset.Position(kv.Pos())))
			}
		}
		return true
	})
	return found
}

// noteElidedType records the type an element omitted, for the element to
// read when the walk reaches it.
func noteElidedType(elided map[*ast.CompositeLit]ast.Expr, element ast.Expr, elementType ast.Expr) {
	inner, ok := element.(*ast.CompositeLit)
	if !ok || inner.Type != nil || elementType == nil {
		return
	}
	elided[inner] = elementType
}

// compositeElementTypes reports the types a composite literal's keys and
// elements may omit. Only sequences and maps let an element omit its type.
func compositeElementTypes(typ ast.Expr) (key, value ast.Expr) {
	switch typed := typ.(type) {
	case *ast.ArrayType: // slices and arrays both
		return nil, typed.Elt
	case *ast.MapType:
		return typed.Key, typed.Value
	}
	return nil, nil
}

func isCredentialQueryType(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident: // within this package
		return typed.Name == "CredentialQuery"
	case *ast.SelectorExpr: // openid4vp.CredentialQuery
		return typed.Sel.Name == "CredentialQuery"
	case *ast.StarExpr: // []*CredentialQuery{{...}} means &CredentialQuery{...}
		return isCredentialQueryType(typed.X)
	}
	return false
}

// A literal that omits its element type is the spelling the guard first
// missed: []CredentialQuery{{Raw: raw}} builds exactly what
// CredentialQuery{Raw: raw} builds, and sailed straight past, because the
// inner literal names no type at all.
func TestGuardSeesLiteralsThatOmitTheirType(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"explicit", `_ = CredentialQuery{Raw: raw}`, 1},
		{"qualified", `_ = openid4vp.CredentialQuery{Raw: raw}`, 1},

		{"slice", `_ = []CredentialQuery{{Raw: raw}}`, 1},
		{"slice qualified", `_ = []openid4vp.CredentialQuery{{Raw: raw}}`, 1},
		{"slice of pointers", `_ = []*CredentialQuery{{Raw: raw}}`, 1},
		{"array", `_ = [2]CredentialQuery{{Raw: raw}, {Raw: raw}}`, 2},
		{"slice of slices", `_ = [][]CredentialQuery{{{Raw: raw}}}`, 1},

		{"map value", `_ = map[string]CredentialQuery{"a": {Raw: raw}}`, 1},
		{"map value qualified", `_ = map[string]openid4vp.CredentialQuery{"a": {Raw: raw}}`, 1},
		{"map key", `_ = map[CredentialQuery]bool{{Raw: raw}: true}`, 1},

		// Unkeyed reaches Raw by position without naming it, and omitting
		// the type hides it twice over.
		{"unkeyed in a slice", `_ = []CredentialQuery{{raw}}`, 1},

		// Fail closed: resolving a struct FIELD's elided type needs
		// go/types, so a literal that sets Raw and cannot be attributed is
		// reported rather than assumed innocent.
		{"unresolvable field", `_ = wrapper{Inner: {Raw: raw}}`, 1},

		// Negatives: the guard must not fire on another type that happens
		// to carry a Raw field, nor on a CredentialQuery that leaves Raw
		// alone.
		{"another type in a slice", `_ = []somethingElse{{Raw: raw}}`, 0},
		{"another type in a map", `_ = map[string]somethingElse{"a": {Raw: raw}}`, 0},
		{"no Raw field", `_ = []CredentialQuery{{ID: "x"}}`, 0},
		{"keyed, not Raw", `_ = CredentialQuery{ID: "x"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc f(raw []byte) {\n" + tc.body + "\n}\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
			require.NoError(t, err, "fixture must parse")

			got := rawQueryLiteralViolations(fset, file)
			require.Lenf(t, got, tc.want, "violations for %q: %v", tc.body, got)
		})
	}
}
