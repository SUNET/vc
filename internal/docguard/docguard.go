// Package docguard finds doc comments that describe something other than
// the declaration they sit above.
//
// Inserting a declaration directly above an existing one steals that one's
// doc comment. The result compiles, passes every test, and is invisible in
// a diff - the moved lines show as unchanged context. What it breaks is
// generated documentation describing the wrong thing, which is to say it
// usually does not surface at all.
//
// It exists as a package rather than a helper copied into each test
// because it was copied into each test, and 125 duplicated lines is its
// own kind of maintenance problem.
package docguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Finding is one displaced comment.
type Finding struct {
	// Declaration the comment sits above, or "" for a parenthesised
	// group, which belongs to no single name.
	Declaration string
	// Names is the declaration the comment actually describes.
	Names string
	// Comment is its first line, for the message.
	Comment string
}

func (f Finding) String() string {
	if f.Declaration == "" {
		return fmt.Sprintf("a declaration group carries the doc comment of %q (%q) - "+
			"it was almost certainly inserted between that comment and its declaration",
			f.Names, truncate(f.Comment))
	}
	return fmt.Sprintf("%s: the doc comment above it begins %q - either it documents something else, "+
		"or a declaration was inserted between a comment and the thing it describes",
		f.Declaration, truncate(f.Comment))
}

// Check reports displaced doc comments among the non-test Go files in dir.
//
// The rule is about NAMES rather than positions, which is what lets it
// catch the motivating case: a parenthesised group inserted under a type's
// explanation. A guard that only inspects single declarations skips the
// group entirely, and the type below it is by then undocumented so it is
// skipped too - nothing fails. So every declaration name in the directory
// is collected first, and any doc comment, group or not, that begins with
// a name belonging to a DIFFERENT declaration is displaced.
//
// exempt maps a declaration name to the reason it is allowed to differ -
// a comment carrying a type's former name, say, which is a stale comment
// rather than a displaced one.
//
// Returns the number of comments actually examined alongside the findings,
// so a caller can refuse to pass vacuously.
func Check(dir string, exempt map[string]string) (findings []Finding, checked int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}

	type documented struct {
		owner string
		doc   *ast.CommentGroup
	}
	var docs []documented
	names := map[string]bool{}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, filepath.Clean(name)), nil, parser.ParseComments)
		if parseErr != nil {
			return nil, 0, parseErr
		}
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

	for _, d := range docs {
		first := strings.TrimSpace(strings.TrimPrefix(d.doc.List[0].Text, "//"))
		subject := strings.FieldsFunc(first, func(r rune) bool { return r == ' ' || r == ',' || r == '.' })
		if len(subject) == 0 {
			continue
		}
		named := subject[0]

		if d.owner != "" {
			if _, ok := exempt[d.owner]; ok {
				continue
			}
			checked++
			if named != d.owner {
				findings = append(findings, Finding{Declaration: d.owner, Names: named, Comment: first})
			}
			continue
		}
		// A parenthesised group documents itself, so a declaration name
		// here is a comment that belonged to something else.
		if names[named] {
			checked++
			findings = append(findings, Finding{Names: named, Comment: first})
		}
	}

	return findings, checked, nil
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
