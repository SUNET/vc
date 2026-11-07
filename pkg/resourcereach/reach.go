// Package resourcereach states what a subject reaches under SPOCP endpoint rules, for
// stores that must filter on it.
package resourcereach

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/spocputil"

	"github.com/sirosfoundation/go-spocp/pkg/compare"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

// IdentityMappingScope is the scope SPOCP rules name for identity mappings,
// which hold an authentic_source and no scope.
const IdentityMappingScope = "identity_mapping"

// Positions in a rule, in the order of RuleDimensions.
const (
	ruleService = iota
	ruleMethod
	rulePath
	ruleSubject
	ruleAuthenticSource
	ruleScope
)

// RuleDimensions lists the tagged sub-lists that every SPOCP endpoint rule must
// contain, in positional order. All six parts are mandatory: use * as wildcard for
// fields you don't want to restrict.
func RuleDimensions() []string {
	return []string{"service", "method", "path", "subject", "authentic_source", "scope"}
}

// Value is one position of a Pair: one exact value or any value. The zero value is
// the exact empty string, which no stored document holds.
type Value struct {
	value    string
	anyValue bool
}

// Exact returns the value and true, or false when any value is accepted.
func (v Value) Exact() (string, bool) {
	return v.value, !v.anyValue
}

// Pair is an (authentic_source, scope) combination a store can filter on.
type Pair struct {
	AuthenticSource Value
	Scope           Value
}

// grant is one accepted combination of a rule's source and scope terms. A term is
// an atom, a wildcard, or a form a store cannot express. It is never a set.
type grant struct {
	source sexp.Element
	scope  sexp.Element
}

// Reach states what a subject reaches. It is the residual of the rules
// after partial evaluation on the service, method, path and subject.
//
// It holds nothing, everything, or a set of pairs. The zero value reaches nothing.
// Pairs leaves out a prefix or suffix form: a store compares it under its own
// collation and regex rules, and the filter must stay within the policy. Selecting
// turns such a form into an exact pair for a value the request names.
type Reach struct {
	grants []grant
}

// Everything returns the reach of a request that SPOCP rules do not govern.
func Everything() Reach {
	return Reach{grants: []grant{{source: &starform.Wildcard{}, scope: &starform.Wildcard{}}}}
}

// Nothing reports that no rule accepts this subject on this request.
func (r Reach) Nothing() bool {
	return len(r.grants) == 0
}

// Everything reports that every pair is reached, so a store applies no pair condition.
func (r Reach) Everything() bool {
	return slices.ContainsFunc(r.grants, func(g grant) bool {
		return isWildcard(g.source) && isWildcard(g.scope)
	})
}

// Pairs returns the distinct pairs a store can filter on. No pair means the
// store returns no document.
func (r Reach) Pairs() []Pair {
	pairs := make([]Pair, 0, len(r.grants))
	for _, g := range r.grants {
		source, sourceOK := resourceValueOf(g.source)
		scope, scopeOK := resourceValueOf(g.scope)
		if sourceOK && scopeOK {
			pairs = append(pairs, Pair{AuthenticSource: source, Scope: scope})
		}
	}
	return distinct(pairs)
}

// Selecting returns the reach within the values a request names. An empty value
// names nothing. A named value is compared as the engine compares it, so a prefix
// or suffix form that accepts it becomes an exact pair.
func (r Reach) Selecting(source, scope string) Reach {
	selected := Reach{}
	for _, g := range r.grants {
		sourceTerm, sourceOK := selectTerm(g.source, source)
		scopeTerm, scopeOK := selectTerm(g.scope, scope)
		if sourceOK && scopeOK {
			selected.grants = append(selected.grants, grant{source: sourceTerm, scope: scopeTerm})
		}
	}
	return selected
}

// ReachesScope reports whether a rule accepts scope with some source.
func (r Reach) ReachesScope(scope string) bool {
	return !r.Selecting("", scope).Nothing()
}

// SourcesForScope returns the exact sources paired with scope, or true when
// every source is.
func (r Reach) SourcesForScope(scope string) (sources []string, everySource bool) {
	sources = []string{}
	for _, g := range r.Selecting("", scope).grants {
		if isWildcard(g.source) {
			return nil, true
		}
		if source, ok := g.source.(*sexp.Atom); ok {
			sources = append(sources, source.Value)
		}
	}
	return distinct(sources), false
}

// SourcesAmong returns the exact sources of the reach, followed by each member
// of known that a rule accepts.
func (r Reach) SourcesAmong(known []string) []string {
	sources := []string{}
	for _, g := range r.grants {
		if source, ok := g.source.(*sexp.Atom); ok {
			sources = append(sources, source.Value)
		}
	}
	for _, source := range known {
		if !r.Selecting(source, "").Nothing() {
			sources = append(sources, source)
		}
	}
	return distinct(sources)
}

// distinct returns the first occurrence of each value, in order.
func distinct[T comparable](values []T) []T {
	seen := make(map[T]struct{}, len(values))
	kept := make([]T, 0, len(values))
	for _, value := range values {
		if _, repeated := seen[value]; !repeated {
			seen[value] = struct{}{}
			kept = append(kept, value)
		}
	}
	return kept
}

func selectTerm(term sexp.Element, value string) (sexp.Element, bool) {
	if value == "" {
		return term, true
	}
	named := sexp.NewAtom(value)
	if !compare.LessPermissive(named, term) {
		return nil, false
	}
	return named, true
}

func isWildcard(term sexp.Element) bool {
	_, ok := term.(*starform.Wildcard)
	return ok
}

func resourceValueOf(term sexp.Element) (Value, bool) {
	switch v := term.(type) {
	case *sexp.Atom:
		return Value{value: v.Value}, true
	case *starform.Wildcard:
		return Value{anyValue: true}, true
	default:
		return Value{}, false
	}
}

// ruleConstraint is a value a rule position must accept.
type ruleConstraint struct {
	position int
	value    string
}

// Resolve returns what subject reaches on one request, from the rules
// whose service, method, path and subject positions accept it. A nil engine governs
// nothing, so everything is reached.
func Resolve(engine *spocputil.Engine, service, method, path, subject string) (Reach, error) {
	return resolveReach(engine, []ruleConstraint{
		{ruleService, service}, {ruleMethod, method}, {rulePath, path}, {ruleSubject, subject},
	})
}

// ResolveOnAnyRoute returns the union of what subject reaches over
// every method and path of service.
func ResolveOnAnyRoute(engine *spocputil.Engine, service, subject string) (Reach, error) {
	return resolveReach(engine, []ruleConstraint{{ruleService, service}, {ruleSubject, subject}})
}

func resolveReach(engine *spocputil.Engine, constraints []ruleConstraint) (Reach, error) {
	if engine == nil {
		return Everything(), nil
	}
	dimensions := RuleDimensions()
	reach := Reach{}
	for _, rule := range engine.ExportRules() {
		positions, err := rulePositions(rule, len(dimensions))
		if err != nil {
			return Reach{}, err
		}
		accepted := true
		for _, constraint := range constraints {
			query := sexp.NewList(dimensions[constraint.position], sexp.NewAtom(constraint.value))
			accepted = accepted && compare.LessPermissive(query, positions[constraint.position])
		}
		if !accepted {
			continue
		}
		sources, err := positionTerms(positions[ruleAuthenticSource])
		if err != nil {
			return Reach{}, err
		}
		scopes, err := positionTerms(positions[ruleScope])
		if err != nil {
			return Reach{}, err
		}
		for _, source := range sources {
			for _, scope := range scopes {
				reach.grants = append(reach.grants, grant{source: source, scope: scope})
			}
		}
	}
	return reach, nil
}

// rulePositions returns the count positions of a rule. An endpoint engine admits
// only this shape, so another shape is a defect in the engine's construction.
func rulePositions(rule sexp.Element, count int) ([]sexp.Element, error) {
	list, ok := rule.(*sexp.List)
	if !ok || len(list.Elements) != count {
		return nil, fmt.Errorf("SPOCP rule %s does not have the %d positions of an endpoint rule", rule, count)
	}
	return list.Elements, nil
}

// positionTerms returns the terms a position like (scope (* set a b)) accepts.
func positionTerms(position sexp.Element) ([]sexp.Element, error) {
	list, ok := position.(*sexp.List)
	if !ok || len(list.Elements) != 1 {
		return nil, fmt.Errorf("SPOCP rule position %s does not hold one value", position)
	}
	return flattenTerm(list.Elements[0]), nil
}

// flattenTerm expands a set into its members. A nested list accepts no atom in
// the engine's comparison, so it contributes no term.
func flattenTerm(term sexp.Element) []sexp.Element {
	switch v := term.(type) {
	case *sexp.List:
		return nil
	case *starform.Set:
		var terms []sexp.Element
		for _, member := range v.Elements {
			terms = append(terms, flattenTerm(member)...)
		}
		return terms
	default:
		return []sexp.Element{term}
	}
}
