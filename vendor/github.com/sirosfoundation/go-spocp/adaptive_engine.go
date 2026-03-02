package spocp

import (
	"fmt"

	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// AdaptiveEngine automatically chooses between indexed and non-indexed
// query strategies based on ruleset characteristics.
type AdaptiveEngine struct {
	engine *Engine
	stats  AdaptiveStats
}

// AdaptiveStats tracks metrics for adaptive behavior
type AdaptiveStats struct {
	TotalRules      int
	ListRules       int
	AtomRules       int
	UniqueTags      int
	AvgTagFanout    float64
	IndexingEnabled bool
}

const (
	// Thresholds for enabling indexing
	minRulesForIndexing     = 50  // Don't index small rulesets
	minTagCountForIndexing  = 5   // Need enough tags to benefit
	maxAvgFanoutForIndexing = 100 // Don't index if tags aren't selective
)

// New creates a new adaptive SPOCP engine (recommended).
// This is an alias for NewAdaptiveEngine() and is the recommended
// constructor for most use cases. The engine automatically determines
// whether to use indexing based on ruleset characteristics.
//
// For advanced use cases requiring explicit indexing control,
// see NewEngine() and NewEngineWithIndexing().
func New() *AdaptiveEngine {
	return NewAdaptiveEngine()
}

// NewAdaptiveEngine creates a new adaptive SPOCP engine.
// The engine automatically determines whether to use indexing based on
// the characteristics of the rules added.
//
// This is the same as New() - use whichever name you prefer.
func NewAdaptiveEngine() *AdaptiveEngine {
	return &AdaptiveEngine{
		engine: &Engine{
			rules:        make([]sexp.Element, 0),
			tagIndex:     make(map[string][]int),
			atomRules:    make([]int, 0),
			indexEnabled: false, // Start without indexing
		},
		stats: AdaptiveStats{},
	}
}

// AddRule adds a policy rule and updates adaptive statistics
func (ae *AdaptiveEngine) AddRule(rule string) error {
	parser := sexp.NewParser(rule)
	elem, err := parser.Parse()
	if err != nil {
		return err
	}
	ae.AddRuleElement(elem)
	return nil
}

// AddRuleElement adds a parsed rule element
func (ae *AdaptiveEngine) AddRuleElement(rule sexp.Element) {
	// Always build the index structure for potential use
	idx := len(ae.engine.rules)
	ae.engine.rules = append(ae.engine.rules, rule)

	// Update statistics and index
	ae.stats.TotalRules++

	if list, ok := rule.(*sexp.List); ok {
		ae.stats.ListRules++
		ae.engine.tagIndex[list.Tag] = append(ae.engine.tagIndex[list.Tag], idx)
	} else {
		ae.stats.AtomRules++
		ae.engine.atomRules = append(ae.engine.atomRules, idx)
	}

	// Recalculate whether indexing should be used
	ae.updateIndexingStrategy()
}

// updateIndexingStrategy determines whether to enable indexing
func (ae *AdaptiveEngine) updateIndexingStrategy() {
	// Calculate statistics
	ae.stats.UniqueTags = len(ae.engine.tagIndex)

	// Calculate average fanout (rules per tag)
	if ae.stats.UniqueTags > 0 {
		totalTagged := 0
		for _, indices := range ae.engine.tagIndex {
			totalTagged += len(indices)
		}
		ae.stats.AvgTagFanout = float64(totalTagged) / float64(ae.stats.UniqueTags)
	}

	// Decision logic: enable indexing if:
	// 1. We have enough rules to make indexing worthwhile
	// 2. We have enough unique tags for selectivity
	// 3. Average fanout isn't too high (tags are selective)
	shouldIndex := ae.stats.TotalRules >= minRulesForIndexing &&
		ae.stats.UniqueTags >= minTagCountForIndexing &&
		ae.stats.AvgTagFanout <= maxAvgFanoutForIndexing

	// Update engine's indexing flag
	ae.engine.indexEnabled = shouldIndex
	ae.stats.IndexingEnabled = shouldIndex
}

// Query checks if a query is authorized by any rule
func (ae *AdaptiveEngine) Query(query string) (bool, error) {
	return ae.engine.Query(query)
}

// QueryElement checks if a query element is authorized
func (ae *AdaptiveEngine) QueryElement(query sexp.Element) bool {
	return ae.engine.QueryElement(query)
}

// FindMatchingRules returns all rules that authorize the query
func (ae *AdaptiveEngine) FindMatchingRules(query string) ([]sexp.Element, error) {
	return ae.engine.FindMatchingRules(query)
}

// RuleCount returns the number of rules in the engine
func (ae *AdaptiveEngine) RuleCount() int {
	return ae.engine.RuleCount()
}

// Clear removes all rules from the engine
func (ae *AdaptiveEngine) Clear() {
	ae.engine.Clear()
	ae.stats = AdaptiveStats{}
}

// Stats returns the current adaptive statistics
func (ae *AdaptiveEngine) Stats() AdaptiveStats {
	return ae.stats
}

// GetIndexStats returns indexing statistics (for compatibility)
func (ae *AdaptiveEngine) GetIndexStats() map[string]any {
	baseStats := ae.engine.GetIndexStats()

	// Add adaptive-specific stats
	baseStats["adaptive_total_rules"] = ae.stats.TotalRules
	baseStats["adaptive_list_rules"] = ae.stats.ListRules
	baseStats["adaptive_atom_rules"] = ae.stats.AtomRules
	baseStats["adaptive_unique_tags"] = ae.stats.UniqueTags
	baseStats["adaptive_avg_fanout"] = ae.stats.AvgTagFanout
	baseStats["adaptive_indexing_enabled"] = ae.stats.IndexingEnabled

	return baseStats
}

// ForceIndexing allows manual override of the adaptive strategy
func (ae *AdaptiveEngine) ForceIndexing(enabled bool) {
	ae.engine.indexEnabled = enabled
	ae.stats.IndexingEnabled = enabled
}

// LoadRulesFromFile loads rules from a file into the adaptive engine
func (ae *AdaptiveEngine) LoadRulesFromFile(filename string) error {
	rules, err := persist.LoadFileToSlice(filename)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	for _, rule := range rules {
		ae.AddRuleElement(rule)
	}

	return nil
}

// LoadRulesFromFileWithOptions loads rules with custom options
func (ae *AdaptiveEngine) LoadRulesFromFileWithOptions(filename string, opts persist.LoadOptions) error {
	rules, err := persist.LoadFile(filename, opts)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	for _, rule := range rules {
		ae.AddRuleElement(rule)
	}

	return nil
}

// SaveRulesToFile saves all rules from the engine to a file
func (ae *AdaptiveEngine) SaveRulesToFile(filename string, format persist.FileFormat) error {
	return ae.engine.SaveRulesToFile(filename, format)
}

// ExportRules returns all rules as a slice for serialization
func (ae *AdaptiveEngine) ExportRules() []sexp.Element {
	return ae.engine.ExportRules()
}

// ImportRules replaces all rules with the provided slice
func (ae *AdaptiveEngine) ImportRules(rules []sexp.Element) {
	ae.Clear()
	for _, rule := range rules {
		ae.AddRuleElement(rule)
	}
}
