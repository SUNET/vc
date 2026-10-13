package configuration

import (
	"fmt"
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
// with their own name, and group comments that start with some OTHER
// declaration's name.
//
// The second half is the one that matters, and the first version of this
// guard did not have it. Inserting a declaration directly above an
// existing one steals that one's doc comment, and the result compiles,
// passes every test, and is invisible in a diff - the moved lines show as
// unchanged context. The motivating case was a `const (...)` group
// inserted under BBSConfig's explanation, and a guard that only inspects
// single declarations skips a parenthesised group entirely: the group is
// not checked, and the type below it is now undocumented so it is not
// checked either. Nothing fails.
//
// So the rule is about names rather than positions. Every declaration
// name in the package is collected first; any doc comment - group or not -
// that begins with a name belonging to a DIFFERENT declaration is a
// displaced comment.
func docCommentNames(t *testing.T, exempt map[string]string) {
	t.Helper()

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	type documented struct {
		owner string // "" for a parenthesised group, which belongs to no one name
		doc   *ast.CommentGroup
	}
	var docs []documented
	names := map[string]bool{}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ParseComments)
		require.NoError(t, err)

		for _, decl := range file.Decls {
			owner, doc, declared := declDoc(decl)
			for _, n := range declared {
				names[n] = true
			}
			if doc != nil && len(doc.List) > 0 {
				docs = append(docs, documented{owner: owner, doc: doc})
			}
		}
	}

	require.NotEmpty(t, docs, "no documented declarations found; this guard would pass vacuously")

	checked := 0
	for _, d := range docs {
		first := strings.TrimSpace(strings.TrimPrefix(d.doc.List[0].Text, "//"))
		subject := strings.FieldsFunc(first, func(r rune) bool { return r == ' ' || r == ',' || r == '.' })
		if len(subject) == 0 {
			continue
		}
		named := subject[0]

		if why, ok := exempt[d.owner]; ok && d.owner != "" {
			t.Logf("exempt: %s (%s)", d.owner, why)
			continue
		}

		switch {
		case d.owner != "":
			checked++
			assert.Equal(t, d.owner, named,
				"%s: the doc comment above it begins %q - either it documents something else, "+
					"or a declaration was inserted between a comment and the thing it describes",
				d.owner, truncate(first))
		case names[named]:
			// A parenthesised group whose comment names a declaration.
			// Groups document themselves, so a name here is a comment
			// that belonged to something else before an insertion.
			checked++
			assert.Fail(t,
				fmt.Sprintf("a declaration group carries the doc comment of %q (%q) - "+
					"it was almost certainly inserted between that comment and its declaration", named, truncate(first)))
		}
	}
	require.NotZero(t, checked, "nothing was actually checked")
}

// declDoc returns the single name a declaration documents (empty for a
// parenthesised group), its doc comment, and every name it declares.
func declDoc(decl ast.Decl) (owner string, doc *ast.CommentGroup, declared []string) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil {
			return "", nil, nil
		}
		return d.Name.Name, d.Doc, []string{d.Name.Name}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				declared = append(declared, s.Name.Name)
			case *ast.ValueSpec:
				for _, n := range s.Names {
					declared = append(declared, n.Name)
				}
			}
		}
		// A parenthesised block, or one holding several names, documents
		// the group rather than any single declaration.
		if d.Lparen.IsValid() || len(declared) != 1 {
			return "", d.Doc, declared
		}
		return declared[0], d.Doc, declared
	}
	return "", nil, nil
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
