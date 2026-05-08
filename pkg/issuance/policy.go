package issuance

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/SUNET/vc/pkg/model"

	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// PolicyEngine wraps a SPOCP engine for credential issuance policy evaluation.
type PolicyEngine struct {
	mu     sync.RWMutex
	engine *spocp.AdaptiveEngine
}

// NewPolicyEngine creates a PolicyEngine from an IssuancePolicy configuration.
// Returns nil if no policy is configured (no rules).
func NewPolicyEngine(policy *model.IssuancePolicy) (*PolicyEngine, error) {
	if policy == nil {
		return nil, nil
	}

	hasInline := len(policy.Rules) > 0
	hasFile := policy.RulesFile != ""

	if !hasInline && !hasFile {
		return nil, nil
	}

	engine := spocp.New()

	for i, r := range policy.Rules {
		elem, err := ParseAdvancedSExp(r)
		if err != nil {
			return nil, fmt.Errorf("invalid inline issuance policy rule #%d: %w", i+1, err)
		}
		engine.AddRuleElement(elem)
	}

	if hasFile {
		if err := loadRulesFromFile(engine, policy.RulesFile); err != nil {
			return nil, fmt.Errorf("failed to load issuance policy rules from %s: %w", policy.RulesFile, err)
		}
	}

	return &PolicyEngine{engine: engine}, nil
}

// engineCache caches PolicyEngine instances by IssuancePolicy pointer.
// Config is loaded once at startup and pointers are stable, so pointer identity
// is a safe cache key. This avoids re-parsing rules on every OIDC callback.
var engineCache sync.Map

// GetPolicyEngine returns a cached PolicyEngine for the given policy, creating one if needed.
func GetPolicyEngine(policy *model.IssuancePolicy) (*PolicyEngine, error) {
	if policy == nil {
		return nil, nil
	}

	if cached, ok := engineCache.Load(policy); ok {
		return cached.(*PolicyEngine), nil
	}

	engine, err := NewPolicyEngine(policy)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, nil
	}

	actual, _ := engineCache.LoadOrStore(policy, engine)
	return actual.(*PolicyEngine), nil
}

// Evaluate checks if the given claims satisfy the issuance policy for the specified scope.
// Returns nil if authorized, or an error describing why issuance was denied.
func (pe *PolicyEngine) Evaluate(scope string, claims map[string]any, queryTemplate []model.QueryDimension) error {
	query := BuildQuery(scope, claims, queryTemplate)

	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if !pe.engine.QueryElement(query) {
		return fmt.Errorf("issuance policy denied: claims do not satisfy any rule for scope %q", scope)
	}
	return nil
}

// BuildQuery constructs a SPOCP query S-expression from credential scope and OIDC claims.
// The query has the form: (credential (scope <scope>) (claim1 <value1>) (claim2 <value2>) ...)
func BuildQuery(scope string, claims map[string]any, queryTemplate []model.QueryDimension) sexp.Element {
	elements := []sexp.Element{
		sexp.NewList("scope", sexp.NewAtom(scope)),
	}

	if len(queryTemplate) > 0 {
		// Use explicit template: iterate in defined order to match rule positions
		for _, dim := range queryTemplate {
			if value, ok := claims[dim.Claim]; ok {
				elements = append(elements, sexp.NewList(dim.Dimension, sexp.NewAtom(toStringValue(value))))
			} else {
				// Claim not present — include empty dimension (matches wildcard rules)
				elements = append(elements, sexp.NewList(dim.Dimension))
			}
		}
	} else {
		// Default: include all claims as dimensions, sorted by key for deterministic ordering
		keys := make([]string, 0, len(claims))
		for k := range claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, claimName := range keys {
			elements = append(elements, sexp.NewList(claimName, sexp.NewAtom(toStringValue(claims[claimName]))))
		}
	}

	return sexp.NewList("credential", elements...)
}

func toStringValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%g", val)
	case int:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func loadRulesFromFile(engine *spocp.AdaptiveEngine, path string) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		elem, err := ParseAdvancedSExp(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
		engine.AddRuleElement(elem)
	}
	return scanner.Err()
}
