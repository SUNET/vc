package apiv1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Commitments are injected BEFORE the format dispatch, so no signing
// path can be reached without them.
//
// A position guard rather than a behavioural test because the failure it
// catches is an ABSENCE: a scope configures a commitment claim, startup
// accepts it, and the credential is signed without the claim. Nothing
// fails, nobody is told, and the credential is wrong in a way that only
// surfaces when a wallet tries to prove with it.
//
// It was absent twice when the injection lived in the issuer and each
// signing path had to remember it - MakeVC20 and MakeJWP both signed the
// document unchanged. Moving it in front of the dispatch is what makes
// "every path" true by construction rather than by four separate call
// sites agreeing; this guard is what keeps the one call site in front of
// the fork.
func TestCommitmentsAreInjectedBeforeTheFormatDispatch(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "handlers_issuer.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	var dispatcher *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "VCICredential" {
			dispatcher = fn
		}
		return dispatcher == nil
	})
	require.NotNil(t, dispatcher, "no VCICredential in handlers_issuer.go; this guard is not looking at anything")

	var injectAt, switchAt token.Pos
	var issueCalls []string
	ast.Inspect(dispatcher, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				switch name := sel.Sel.Name; {
				case name == "injectCommitments" && !injectAt.IsValid():
					injectAt = node.Pos()
				case len(name) > 5 && name[:5] == "issue":
					issueCalls = append(issueCalls, name)
				}
			}
		case *ast.SwitchStmt:
			// The format dispatch is the switch whose body calls the
			// issue* helpers; take the first one that does.
			if !switchAt.IsValid() && switchDispatchesOnFormat(node) {
				switchAt = node.Pos()
			}
		}
		return true
	})

	require.True(t, injectAt.IsValid(), "VCICredential does not call injectCommitments at all")
	require.True(t, switchAt.IsValid(), "no format dispatch found; this guard is not looking at anything")
	assert.Less(t, int(injectAt), int(switchAt),
		"injectCommitments must run BEFORE the format dispatch, or a signing path can be reached without it")

	// And every format really is reached through that switch, so being
	// in front of it means being in front of all of them.
	assert.GreaterOrEqual(t, len(issueCalls), 4,
		"expected every issue* path to be dispatched here; got %v", issueCalls)
}

// switchDispatchesOnFormat reports whether this switch is the one that
// picks a signing path.
func switchDispatchesOnFormat(sw *ast.SwitchStmt) bool {
	found := false
	ast.Inspect(sw.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if name := sel.Sel.Name; len(name) > 5 && name[:5] == "issue" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
