// Package spocp provides a generalized authorization engine based on restricted S-expressions.
// It implements the SPOCP (Simple Policy Control Protocol) specification for policy evaluation.
package spocp

import (
	"fmt"

	"github.com/sirosfoundation/go-spocp/pkg/compare"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// Engine is the main SPOCP policy engine
type Engine struct {
	rules        []sexp.Element
	tagIndex     map[string][]int // tag -> slice of rule indices
	atomRules    []int            // indices of non-list rules
	indexEnabled bool             // whether to use indexing
}

// NewEngine creates a new SPOCP engine with indexing enabled by default
func NewEngine() *Engine {
	return &Engine{
		rules:        make([]sexp.Element, 0),
		tagIndex:     make(map[string][]int),
		atomRules:    make([]int, 0),
		indexEnabled: true,
	}
}

// NewEngineWithIndexing creates a new SPOCP engine with optional indexing
func NewEngineWithIndexing(enableIndex bool) *Engine {
	return &Engine{
		rules:        make([]sexp.Element, 0),
		tagIndex:     make(map[string][]int),
		atomRules:    make([]int, 0),
		indexEnabled: enableIndex,
	}
}

// AddRule adds a policy rule to the engine
func (e *Engine) AddRule(rule string) error {
	parser := sexp.NewParser(rule)
	elem, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse rule: %v", err)
	}
	e.AddRuleElement(elem)
	return nil
}

// AddRuleElement adds a parsed rule element to the engine
func (e *Engine) AddRuleElement(rule sexp.Element) {
	idx := len(e.rules)
	e.rules = append(e.rules, rule)

	// Update index if enabled
	if e.indexEnabled {
		if list, ok := rule.(*sexp.List); ok {
			// List rule - index by tag
			e.tagIndex[list.Tag] = append(e.tagIndex[list.Tag], idx)
		} else {
			// Atom or star form - keep in separate list
			e.atomRules = append(e.atomRules, idx)
		}
	}
}

// Query checks if a query is authorized by any rule in the engine.
// Returns true if there exists a rule R such that query <= R.
func (e *Engine) Query(query string) (bool, error) {
	parser := sexp.NewParser(query)
	queryElem, err := parser.Parse()
	if err != nil {
		return false, fmt.Errorf("failed to parse query: %v", err)
	}
	return e.QueryElement(queryElem), nil
}

// QueryElement checks if a query element is authorized
func (e *Engine) QueryElement(query sexp.Element) bool {
	if e.indexEnabled {
		return e.queryIndexed(query)
	}
	return e.queryLinear(query)
}

// queryLinear performs linear search through all rules (original implementation)
func (e *Engine) queryLinear(query sexp.Element) bool {
	for _, rule := range e.rules {
		if compare.LessPermissive(query, rule) {
			return true
		}
	}
	return false
}

// queryIndexed uses tag-based index for faster lookup
func (e *Engine) queryIndexed(query sexp.Element) bool {
	// Fast path: if query is a list, only check rules with matching tag
	if list, ok := query.(*sexp.List); ok {
		return e.queryByTag(query, list.Tag)
	}

	// For atoms and star forms, check all non-list rules
	for _, idx := range e.atomRules {
		if compare.LessPermissive(query, e.rules[idx]) {
			return true
		}
	}
	return false
}

// queryByTag checks only rules with matching tag
func (e *Engine) queryByTag(query sexp.Element, tag string) bool {
	// Check rules with matching tag
	if indices, exists := e.tagIndex[tag]; exists {
		for _, idx := range indices {
			if compare.LessPermissive(query, e.rules[idx]) {
				return true
			}
		}
	}
	return false
}

// FindMatchingRules returns all rules that authorize the query
func (e *Engine) FindMatchingRules(query string) ([]sexp.Element, error) {
	parser := sexp.NewParser(query)
	queryElem, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %v", err)
	}

	var matches []sexp.Element

	if e.indexEnabled {
		// Use indexed search
		if list, ok := queryElem.(*sexp.List); ok {
			// Query is a list - use tag index
			if indices, exists := e.tagIndex[list.Tag]; exists {
				for _, idx := range indices {
					if compare.LessPermissive(queryElem, e.rules[idx]) {
						matches = append(matches, e.rules[idx])
					}
				}
			}
		} else {
			// Query is atom/star form - check atom rules
			for _, idx := range e.atomRules {
				if compare.LessPermissive(queryElem, e.rules[idx]) {
					matches = append(matches, e.rules[idx])
				}
			}
		}
	} else {
		// Linear search
		for _, rule := range e.rules {
			if compare.LessPermissive(queryElem, rule) {
				matches = append(matches, rule)
			}
		}
	}

	return matches, nil
}

// RuleCount returns the number of rules in the engine
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// Clear removes all rules from the engine
func (e *Engine) Clear() {
	e.rules = make([]sexp.Element, 0)
	if e.indexEnabled {
		e.tagIndex = make(map[string][]int)
		e.atomRules = make([]int, 0)
	}
}

// GetIndexStats returns statistics about the tag index
func (e *Engine) GetIndexStats() map[string]any {
	stats := make(map[string]any)
	stats["total_rules"] = len(e.rules)
	stats["index_enabled"] = e.indexEnabled

	if e.indexEnabled {
		stats["unique_tags"] = len(e.tagIndex)
		stats["atom_rules"] = len(e.atomRules)

		// Calculate average rules per tag
		if len(e.tagIndex) > 0 {
			total := 0
			for _, indices := range e.tagIndex {
				total += len(indices)
			}
			stats["avg_rules_per_tag"] = float64(total) / float64(len(e.tagIndex))
		}

		// Find most common tag
		maxCount := 0
		maxTag := ""
		for tag, indices := range e.tagIndex {
			if len(indices) > maxCount {
				maxCount = len(indices)
				maxTag = tag
			}
		}
		if maxTag != "" {
			stats["most_common_tag"] = maxTag
			stats["most_common_tag_count"] = maxCount
		}
	}

	return stats
}
