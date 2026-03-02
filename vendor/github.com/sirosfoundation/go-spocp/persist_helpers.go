package spocp

import (
	"fmt"

	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// LoadRulesFromFile loads rules from a file into the engine
func (e *Engine) LoadRulesFromFile(filename string) error {
	rules, err := persist.LoadFileToSlice(filename)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	for _, rule := range rules {
		e.AddRuleElement(rule)
	}

	return nil
}

// LoadRulesFromFileWithOptions loads rules with custom options
func (e *Engine) LoadRulesFromFileWithOptions(filename string, opts persist.LoadOptions) error {
	rules, err := persist.LoadFile(filename, opts)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	for _, rule := range rules {
		e.AddRuleElement(rule)
	}

	return nil
}

// SaveRulesToFile saves all rules from the engine to a file
func (e *Engine) SaveRulesToFile(filename string, format persist.FileFormat) error {
	return persist.SaveFile(filename, e.rules, format)
}

// ExportRules returns all rules as a slice for serialization
func (e *Engine) ExportRules() []sexp.Element {
	// Return a copy to prevent external modification
	exported := make([]sexp.Element, len(e.rules))
	copy(exported, e.rules)
	return exported
}

// ImportRules replaces all rules with the provided slice
func (e *Engine) ImportRules(rules []sexp.Element) {
	e.Clear()
	for _, rule := range rules {
		e.AddRuleElement(rule)
	}
}
