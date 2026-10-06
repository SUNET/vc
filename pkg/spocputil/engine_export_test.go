package spocputil

import (
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"

	"github.com/stretchr/testify/require"
)

// TestExportRulesDeepCopies: the wrapper's whole promise is that a caller
// can read the rule set without holding its lock. slices.Clone copied the
// top-level slice and left every *sexp.List, *sexp.Atom and star form
// shared - so a caller could reach into a returned rule and overwrite an
// element in place, changing authorization for everyone and racing a
// concurrent QueryElement while doing it.
func TestExportRulesDeepCopies(t *testing.T) {
	engine, err := BuildEngine("vc", nil, false, "test", []string{
		"(vc (method GET)(path /api/v1)(subject alice)(authentic_source SUNET)(scope pid))",
	}, "")
	require.NoError(t, err)
	require.NotNil(t, engine)

	first := engine.ExportRules()
	require.NotEmpty(t, first)

	// Mutate everything reachable from the returned tree.
	mutate(first)

	second := engine.ExportRules()
	require.Equal(t, len(first), len(second))
	require.NotEqual(t, renderAll(first), renderAll(second),
		"mutating the returned rules must not be visible in the engine's own")

	// And the engine still answers on the unmutated policy.
	require.True(t, engine.QueryElement(sexp.NewList("vc",
		sexp.NewList("method", sexp.NewAtom("GET")),
		sexp.NewList("path", sexp.NewAtom("/api/v1")),
		sexp.NewList("subject", sexp.NewAtom("alice")),
		sexp.NewList("authentic_source", sexp.NewAtom("SUNET")),
		sexp.NewList("scope", sexp.NewAtom("pid")),
	)))
}

func mutate(elements []sexp.Element) {
	for _, element := range elements {
		switch v := element.(type) {
		case *sexp.Atom:
			v.Value = "mutated"
		case *sexp.List:
			v.Tag = "mutated"
			mutate(v.Elements)
		case *starform.Set:
			mutate(v.Elements)
		case *starform.Prefix:
			v.Value = "mutated"
		case *starform.Suffix:
			v.Value = "mutated"
		}
	}
}

func renderAll(elements []sexp.Element) string {
	out := ""
	for _, element := range elements {
		out += element.String()
	}
	return out
}

// TestCloneElementHandlesEveryStarForm names each type explicitly, so a new
// element type in go-spocp shows up here rather than silently taking the
// shared-value default.
func TestCloneElementHandlesEveryStarForm(t *testing.T) {
	bound := &starform.RangeBound{Op: starform.OpGE, Value: "1"}
	original := sexp.NewList("rule",
		sexp.NewAtom("a"),
		&starform.Wildcard{},
		&starform.Set{Elements: []sexp.Element{sexp.NewAtom("b")}},
		&starform.Range{RangeType: starform.RangeNumeric, LowerBound: bound},
		&starform.Prefix{Value: "p"},
		&starform.Suffix{Value: "s"},
	)

	clone, ok := cloneElement(original).(*sexp.List)
	require.True(t, ok)
	require.Equal(t, original.String(), clone.String(), "a clone renders identically")

	// Nothing in the clone shares storage with the original.
	mutate([]sexp.Element{clone})
	require.NotEqual(t, original.String(), clone.String())

	// The Range's bounds are copied rather than aliased.
	clonedRange, ok := cloneElement(&starform.Range{RangeType: starform.RangeNumeric, LowerBound: bound}).(*starform.Range)
	require.True(t, ok)
	require.NotSame(t, bound, clonedRange.LowerBound)
	require.Equal(t, bound.Value, clonedRange.LowerBound.Value)
}
