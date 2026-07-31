package issuance

import (
	"fmt"
	"sort"
	"sync"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/spocputil"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// PolicyEngine wraps a shared spocputil.Engine for credential issuance
// policy evaluation. The engine type itself is shared with
// pkg/httphelpers' endpoint-access SPOCP rules (see spocputil.Engine), so
// both endpoint rules and issuance policy rules are built, validated, and
// queried through the same machinery.
type PolicyEngine struct {
	engine *spocputil.Engine
}

// scopeDimension is always the first dimension in a "credential" query/rule,
// regardless of QueryTemplate, matching BuildQuery's fixed ordering.
const scopeDimension = "scope"

// policyRuleDimensions returns the ordered dimension list a rule must match
// for the given QueryTemplate, for validation purposes. Returns nil when no
// QueryTemplate is configured: in that mode BuildQuery emits one dimension
// per OIDC claim present on a given request, so the dimension set isn't
// statically fixed and can't be validated up front.
func policyRuleDimensions(queryTemplate []model.QueryDimension) []string {
	if len(queryTemplate) == 0 {
		return nil
	}
	dims := make([]string, 0, len(queryTemplate)+1)
	dims = append(dims, scopeDimension)
	for _, d := range queryTemplate {
		dims = append(dims, d.Dimension)
	}
	return dims
}

// NewPolicyEngine creates a PolicyEngine from an IssuancePolicy configuration.
// Returns nil if no policy is configured (no rules).
func NewPolicyEngine(policy *model.IssuancePolicy) (*PolicyEngine, error) {
	if policy == nil {
		return nil, nil
	}

	dims := policyRuleDimensions(policy.QueryTemplate)
	engine, err := spocputil.BuildEngine("credential", dims, false, "issuance policy", policy.Rules, policy.RulesFile)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, nil
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

	if !pe.engine.QueryElement(query) {
		return fmt.Errorf("issuance policy denied: claims do not satisfy any rule for scope %q", scope)
	}
	return nil
}

// BuildQuery constructs a SPOCP query S-expression from credential scope and OIDC claims.
// The query has the form: (credential (scope <scope>) (claim1 <value1>) (claim2 <value2>) ...)
func BuildQuery(scope string, claims map[string]any, queryTemplate []model.QueryDimension) sexp.Element {
	dims := make([]string, 0, len(queryTemplate)+1)
	dims = append(dims, scopeDimension)
	values := map[string]string{scopeDimension: scope}

	if len(queryTemplate) > 0 {
		// Use explicit template: iterate in defined order to match rule positions
		for _, dim := range queryTemplate {
			dims = append(dims, dim.Dimension)
			if value, ok := claims[dim.Claim]; ok {
				values[dim.Dimension] = toStringValue(value)
			}
			// Claim not present — leave values[dim.Dimension] unset;
			// BuildTaggedQuery emits an empty dimension, matching wildcard rules.
		}
	} else {
		// Default: include all claims as dimensions, sorted by key for deterministic ordering
		keys := make([]string, 0, len(claims))
		for k := range claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, claimName := range keys {
			dims = append(dims, claimName)
			values[claimName] = toStringValue(claims[claimName])
		}
	}

	return spocputil.BuildTaggedQuery("credential", dims, values)
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
