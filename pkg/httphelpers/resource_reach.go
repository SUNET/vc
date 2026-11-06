package httphelpers

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-spocp/pkg/compare"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

// IdentityMappingScope is the scope SPOCP rules name for identity mappings,
// which hold an authentic_source and no scope.
const IdentityMappingScope = "identity_mapping"

// resourceReachKey is the gin context key of the request's ResourceReach.
const resourceReachKey = "spocp_resource_reach"

// Positions in a rule, in the order of apiAuthRuleDimensions.
const (
	ruleService = iota
	ruleMethod
	rulePath
	ruleSubject
	ruleAuthenticSource
	ruleScope
)

// ResourceValue is one position of a ResourcePair: one exact value or any value.
type ResourceValue struct {
	value string
	exact bool
}

// Exact returns the value and true, or false when any value is accepted.
func (v ResourceValue) Exact() (string, bool) {
	return v.value, v.exact
}

// ResourcePair is an (authentic_source, scope) combination a store can filter on.
type ResourcePair struct {
	AuthenticSource ResourceValue
	Scope           ResourceValue
}

// resourceGrant is one accepted combination of a rule's source and scope terms.
// A term is an atom, a wildcard, or a form a store cannot express. It is never a set.
type resourceGrant struct {
	source sexp.Element
	scope  sexp.Element
}

// ResourceReach states what a subject reaches. It is the residual of the rules
// after partial evaluation on the service, method, path and subject.
//
// It holds nothing, everything, or a set of pairs. The zero value reaches nothing.
// Pairs leaves out a prefix or suffix form: a store compares it under its own
// collation and regex rules, and the filter must stay within the policy. Selecting
// turns such a form into an exact pair for a value the request names.
type ResourceReach struct {
	grants []resourceGrant
}

// ReachEverything returns the reach of a request that SPOCP rules do not govern.
func ReachEverything() ResourceReach {
	return ResourceReach{grants: []resourceGrant{{source: &starform.Wildcard{}, scope: &starform.Wildcard{}}}}
}

// Nothing reports that no rule accepts this subject on this request.
func (r ResourceReach) Nothing() bool {
	return len(r.grants) == 0
}

// Everything reports that every pair is reached, so a store applies no pair condition.
func (r ResourceReach) Everything() bool {
	return slices.ContainsFunc(r.grants, func(g resourceGrant) bool {
		return isWildcard(g.source) && isWildcard(g.scope)
	})
}

// Pairs returns the distinct pairs a store can filter on. No pair means the
// store returns no document.
func (r ResourceReach) Pairs() []ResourcePair {
	pairs := []ResourcePair{}
	for _, g := range r.grants {
		source, sourceOK := resourceValueOf(g.source)
		scope, scopeOK := resourceValueOf(g.scope)
		pair := ResourcePair{AuthenticSource: source, Scope: scope}
		if sourceOK && scopeOK && !slices.Contains(pairs, pair) {
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

// Selecting returns the reach within the values a request names. An empty value
// names nothing. A named value is compared as the engine compares it, so a prefix
// or suffix form that accepts it becomes an exact pair.
func (r ResourceReach) Selecting(source, scope string) ResourceReach {
	selected := ResourceReach{}
	for _, g := range r.grants {
		sourceTerm, sourceOK := selectTerm(g.source, source)
		scopeTerm, scopeOK := selectTerm(g.scope, scope)
		if sourceOK && scopeOK {
			selected.grants = append(selected.grants, resourceGrant{source: sourceTerm, scope: scopeTerm})
		}
	}
	return selected
}

// ReachesScope reports whether a rule accepts scope with some source.
func (r ResourceReach) ReachesScope(scope string) bool {
	return !r.Selecting("", scope).Nothing()
}

// SourcesForScope returns the exact sources paired with scope, or true when
// every source is.
func (r ResourceReach) SourcesForScope(scope string) (sources []string, everySource bool) {
	sources = []string{}
	for _, g := range r.Selecting("", scope).grants {
		if isWildcard(g.source) {
			return nil, true
		}
		if source, ok := g.source.(*sexp.Atom); ok && !slices.Contains(sources, source.Value) {
			sources = append(sources, source.Value)
		}
	}
	return sources, false
}

// SourcesAmong returns the exact sources of the reach, followed by each member
// of known that a rule accepts.
func (r ResourceReach) SourcesAmong(known []string) []string {
	sources := []string{}
	add := func(source string) {
		if !slices.Contains(sources, source) {
			sources = append(sources, source)
		}
	}
	for _, g := range r.grants {
		if source, ok := g.source.(*sexp.Atom); ok {
			add(source.Value)
		}
	}
	for _, source := range known {
		if !r.Selecting(source, "").Nothing() {
			add(source)
		}
	}
	return sources
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

func resourceValueOf(term sexp.Element) (ResourceValue, bool) {
	switch v := term.(type) {
	case *sexp.Atom:
		return ResourceValue{value: v.Value, exact: true}, true
	case *starform.Wildcard:
		return ResourceValue{}, true
	default:
		return ResourceValue{}, false
	}
}

// ruleConstraint is a value a rule position must accept.
type ruleConstraint struct {
	position int
	value    string
}

// ResolveResourceReach returns what subject reaches on one request, from the rules
// whose service, method, path and subject positions accept it. A nil engine governs
// nothing, so everything is reached.
func ResolveResourceReach(engine *SafeEngine, service, method, path, subject string) (ResourceReach, error) {
	return resolveReach(engine, []ruleConstraint{
		{ruleService, service}, {ruleMethod, method}, {rulePath, path}, {ruleSubject, subject},
	})
}

// ResolveResourceReachOnAnyRoute returns the union of what subject reaches over
// every method and path of service.
func ResolveResourceReachOnAnyRoute(engine *SafeEngine, service, subject string) (ResourceReach, error) {
	return resolveReach(engine, []ruleConstraint{{ruleService, service}, {ruleSubject, subject}})
}

func resolveReach(engine *SafeEngine, constraints []ruleConstraint) (ResourceReach, error) {
	if engine == nil {
		return ReachEverything(), nil
	}
	reach := ResourceReach{}
	for _, rule := range engine.ExportRules() {
		positions, err := rulePositions(rule)
		if err != nil {
			return ResourceReach{}, err
		}
		accepted := true
		for _, constraint := range constraints {
			query := sexp.NewList(apiAuthRuleDimensions[constraint.position], sexp.NewAtom(constraint.value))
			accepted = accepted && compare.LessPermissive(query, positions[constraint.position])
		}
		if !accepted {
			continue
		}
		sources, err := positionTerms(positions[ruleAuthenticSource])
		if err != nil {
			return ResourceReach{}, err
		}
		scopes, err := positionTerms(positions[ruleScope])
		if err != nil {
			return ResourceReach{}, err
		}
		for _, source := range sources {
			for _, scope := range scopes {
				reach.grants = append(reach.grants, resourceGrant{source: source, scope: scope})
			}
		}
	}
	return reach, nil
}

// rulePositions returns the positions of a rule. BuildSPOCPEngine admits only
// this shape, so another shape is a defect in the engine's construction.
func rulePositions(rule sexp.Element) ([]sexp.Element, error) {
	list, ok := rule.(*sexp.List)
	if !ok || len(list.Elements) != len(apiAuthRuleDimensions) {
		return nil, fmt.Errorf("SPOCP rule %s does not have the %d positions of an endpoint rule", rule, len(apiAuthRuleDimensions))
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

// bindResourceReach resolves what subject reaches on this request and puts it on
// the context. A failure aborts the request and returns false.
func bindResourceReach(c *gin.Context, engine *SafeEngine, service, subject string, log *logger.Log) (ResourceReach, bool) {
	reach, err := ResolveResourceReach(engine, service, c.Request.Method, c.FullPath(), subject)
	if err != nil {
		log.Error(err, "spocp_reach_failed", "req_id", c.GetString("req_id"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization unavailable"})
		return ResourceReach{}, false
	}
	c.Set(resourceReachKey, reach)
	return reach, true
}

// ResourceReachOf returns the reach the authorization middleware bound. A request
// that passed none of them is an error.
func ResourceReachOf(c *gin.Context) (ResourceReach, error) {
	value, ok := c.Get(resourceReachKey)
	if !ok {
		return ResourceReach{}, fmt.Errorf("context holds no %s: the route has no authorization middleware", resourceReachKey)
	}
	reach, ok := value.(ResourceReach)
	if !ok {
		return ResourceReach{}, fmt.Errorf("context key %s holds %T", resourceReachKey, value)
	}
	return reach, nil
}

// SelectedResourceReach returns the bound reach within the values a request names.
func SelectedResourceReach(c *gin.Context, source, scope string) (ResourceReach, error) {
	reach, err := ResourceReachOf(c)
	if err != nil {
		return ResourceReach{}, err
	}
	return reach.Selecting(source, scope), nil
}
