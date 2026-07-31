package spocputil

import (
	"fmt"
	"sync"

	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// Engine wraps a SPOCP AdaptiveEngine with a mutex, safe for concurrent
// QueryElement/RuleCount/ExportRules access after construction. Shared by
// both HTTP endpoint-access rules (pkg/httphelpers) and OIDC
// credential-issuance policy rules (pkg/issuance), so both rule sets are
// built, validated, and queried through the same machinery rather than each
// maintaining its own copy.
type Engine struct {
	mu     sync.RWMutex
	engine *spocp.AdaptiveEngine
}

// QueryElement checks if the query is authorized (read-locked).
func (e *Engine) QueryElement(q sexp.Element) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.engine.QueryElement(q)
}

// RuleCount returns the number of loaded rules (read-locked).
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.engine.RuleCount()
}

// ExportRules returns the raw parsed rule elements (read-locked), for
// callers that need to inspect rule structure directly (e.g. resolving the
// set of resources a subject is authorized for, rather than just answering
// yes/no for one specific query).
func (e *Engine) ExportRules() []sexp.Element {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.engine.ExportRules()
}

// BuildEngine parses inline rules and an optional rules file into a new
// Engine tagged for this rule set's domain. Returns (nil, nil) when neither
// inline rules nor a rules file are configured.
//
// ruleLabel names the rule set for error messages (e.g. "SPOCP" or
// "issuance policy") so callers get a domain-specific error without each
// needing to re-wrap it.
//
// When dims is non-nil, every rule -- inline and file-loaded alike -- is
// validated against tag/dims via ValidateRuleElement before being added.
// Pass nil to skip shape validation for rule sets whose dimensions aren't
// statically fixed (e.g. an issuance policy with no configured
// QueryTemplate, which queries with whatever OIDC claims happen to be
// present on a given request rather than a fixed, known set of dimensions).
//
// requireValue is forwarded to ValidateRuleElement -- see its doc comment
// for why this can't be a fixed choice shared by every caller.
func BuildEngine(tag string, dims []string, requireValue bool, ruleLabel string, inlineRules []string, rulesFile string) (*Engine, error) {
	hasInline := len(inlineRules) > 0
	hasFile := rulesFile != ""
	if !hasInline && !hasFile {
		return nil, nil
	}

	raw := spocp.New()

	for i, r := range inlineRules {
		elem, err := ParseAdvancedSExp(r)
		if err != nil {
			return nil, fmt.Errorf("invalid inline %s rule #%d: %w", ruleLabel, i+1, err)
		}
		if dims != nil {
			if err := ValidateRuleElement(elem, tag, dims, requireValue, fmt.Sprintf("inline rule #%d", i+1)); err != nil {
				return nil, err
			}
		}
		raw.AddRuleElement(elem)
	}

	if hasFile {
		var validate func(sexp.Element, string) error
		if dims != nil {
			validate = func(elem sexp.Element, source string) error {
				return ValidateRuleElement(elem, tag, dims, requireValue, source)
			}
		}
		if err := LoadRulesFromFile(raw, rulesFile, validate); err != nil {
			return nil, fmt.Errorf("failed to load %s rules from %s: %w", ruleLabel, rulesFile, err)
		}
	}

	return &Engine{engine: raw}, nil
}

// ValidateRuleElement checks that a parsed rule is a list tagged `tag`
// containing exactly len(dims) sub-lists in the given order, each tagged
// with the corresponding dimension name. SPOCP matching is positional, so
// wrong order, wrong count, or an unexpectedly multi-valued part would
// silently never match at query time -- reject those up front instead.
//
// requireValue controls whether a dimension may be written as an empty
// list, e.g. (email_verified), to mean "any value" (SPOCP's native wildcard
// form, and what BuildTaggedQuery itself emits for an absent value):
//   - true: every dimension must hold exactly one value; write the literal
//     atom "*" for wildcards. This is the endpoint-access convention.
//   - false: a dimension may hold zero or one value; more than one is
//     always rejected regardless. This is the issuance-policy convention,
//     which already authors wildcards as empty dimensions.
//
// The two domains' existing rule files use different conventions here, so
// this can't be collapsed into one fixed choice without either breaking
// issuance's existing wildcard style or silently loosening endpoint-access
// validation.
func ValidateRuleElement(elem sexp.Element, tag string, dims []string, requireValue bool, source string) error {
	list, ok := elem.(*sexp.List)
	if !ok {
		return fmt.Errorf("%s: rule must be a list, got %T", source, elem)
	}
	if list.Tag != tag {
		return fmt.Errorf("%s: rule must have tag %q, got %q", source, tag, list.Tag)
	}
	if len(list.Elements) != len(dims) {
		return fmt.Errorf("%s: rule must have exactly %d parts, got %d",
			source, len(dims), len(list.Elements))
	}
	for i, dim := range dims {
		child := list.Elements[i]
		cl, ok := child.(*sexp.List)
		if !ok {
			return fmt.Errorf("%s: part %d must be a list, got %T", source, i+1, child)
		}
		if cl.Tag != dim {
			return fmt.Errorf("%s: part %d must be (%s ...), got (%s ...)",
				source, i+1, dim, cl.Tag)
		}
		switch len(cl.Elements) {
		case 0:
			if requireValue {
				return fmt.Errorf("%s: part (%s) must have exactly 1 value, got 0 (use * as wildcard)",
					source, dim)
			}
		case 1:
			// ok
		default:
			if requireValue {
				return fmt.Errorf("%s: part (%s) must have exactly 1 value, got %d",
					source, dim, len(cl.Elements))
			}
			return fmt.Errorf("%s: part (%s) must have at most 1 value, got %d",
				source, dim, len(cl.Elements))
		}
	}
	return nil
}

// BuildTaggedQuery constructs `(tag (dim1 val1)(dim2 val2)...)` in the given
// dimension order. A dimension with no matching entry in `values` is
// emitted as an empty list `(dim)`, which SPOCP wildcard rules match.
func BuildTaggedQuery(tag string, dims []string, values map[string]string) sexp.Element {
	elements := make([]sexp.Element, 0, len(dims))
	for _, d := range dims {
		if v, ok := values[d]; ok {
			elements = append(elements, sexp.NewList(d, sexp.NewAtom(v)))
		} else {
			elements = append(elements, sexp.NewList(d))
		}
	}
	return sexp.NewList(tag, elements...)
}
