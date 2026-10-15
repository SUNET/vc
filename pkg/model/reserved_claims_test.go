package model

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reserved SD-JWT claim list must cover everything the builder writes
// at the root of the payload.
//
// Derived from the builder's source rather than compared against a list I
// wrote, because the list I wrote was wrong twice: I grepped for one
// variable name and missed "_sd_alg", assigned to another, and "_sd",
// which goes into whatever object a disclosure's parent is - the root,
// for a top-level claim. A commitment at either is replaced after
// injection, and nothing reports it.
//
// If this fails because the builder moved, that is the point: the list
// has to follow it.
func TestReservedSDJWTClaimsCoverTheBuilder(t *testing.T) {
	const builder = "../sdjwtvc/methods.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, builder, nil, 0)
	require.NoError(t, err, "the SD-JWT builder must be parseable at %s; if it moved, point this test at it", builder)

	// Assignments of the form <map>["literal"] = ..., where the map is one
	// of the payload roots the builder populates.
	roots := map[string]bool{"body": true, "data": true, "current": true}
	assigned := map[string]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			index, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			ident, ok := index.X.(*ast.Ident)
			if !ok || !roots[ident.Name] {
				continue
			}
			lit, ok := index.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			assigned[lit.Value[1:len(lit.Value)-1]] = true
		}
		return true
	})

	require.NotEmpty(t, assigned, "no root assignments found; this guard would pass vacuously")

	reserved := reservedTargets[formatFamilySDJWT]
	for claim := range assigned {
		assert.Contains(t, reserved, claim,
			"the SD-JWT builder assigns %q at the payload root, so a commitment configured there "+
				"would be injected and then replaced - add it to reservedTargets", claim)
	}
}
