package apiv1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The identity match is enforced by one line inside
// consumeIssuanceAuthPresentation, and that line cannot be reached by a
// unit test: everything above it is signature verification, issuer trust
// and DCQL matching against a real VP token, and there is no seam in this
// package that produces a verified credential without one.
//
// So this reads the source instead. It is an unusual test and worth
// justifying: the alternative is no executable coverage at all of the
// line that makes a prepared issuance binding, and the two ways that line
// breaks are both visible in the syntax - it gets deleted, or it gets
// moved below the presentation-sourced branch that returns early, which
// would silently exempt exactly the scopes that mint a credential
// straight out of the presentation.
//
// It asserts position, not behaviour, and makes no claim to do more. The
// behaviour of the match itself is covered by TestIdentityMatch_* against
// matchPresentedIdentity directly.
func TestIdentityMatchIsEnforcedBeforeTheEarlyReturn(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "handlers_verifier.go", nil, 0)
	require.NoError(t, err)

	var body *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "consumeIssuanceAuthPresentation" {
			body = fn.Body
			return false
		}
		return true
	})
	require.NotNil(t, body, "consumeIssuanceAuthPresentation not found; this guard needs updating")

	matchPos, finalisePos := token.NoPos, token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "matchPresentedIdentity":
			if !matchPos.IsValid() {
				matchPos = call.Pos()
			}
		case "finalisePresentationVerification":
			if !finalisePos.IsValid() {
				finalisePos = call.Pos()
			}
		}
		return true
	})

	require.True(t, matchPos.IsValid(),
		"consumeIssuanceAuthPresentation no longer calls matchPresentedIdentity, so a prepared issuance binds nothing")
	require.True(t, finalisePos.IsValid(),
		"finalisePresentationVerification is gone; this guard's ordering assumption needs rechecking")

	assert.Less(t, int(matchPos), int(finalisePos),
		"the identity match must run BEFORE the presentation-sourced branch returns, "+
			"or presentation-sourced scopes are exempt from it")
}
