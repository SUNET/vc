package issuance

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/SUNET/vc/pkg/credential"
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
// for the given QueryTemplate. A configured policy always has one (see
// NewPolicyEngine), so this never returns nil for a real policy and rule
// shape is therefore always validated at load time.
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
//
// Returns (nil, nil) only when no policy is configured at all. A policy that
// IS configured but carries no rules is an error, not a silently disabled
// gate: every way of arriving at an empty rule set is an operator mistake,
// and none of them should be discovered at a callback.
//
// There are two such ways, and they used to fail differently. No rules and no
// rules_file made BuildEngine return (nil, nil), which read to every caller
// as "no policy here" - so `issuance_policy: {}` skipped the check it asked
// for. A rules_file that exists but holds nothing parseable (empty, or only
// comments) makes BuildEngine return an engine with zero rules instead, which
// reads as an active policy that no query can ever satisfy - every issuance
// for that scope denied, at runtime, with the config looking fine. Opposite
// symptoms, one cause; both are refused here so they surface at startup, with
// the scope named.
func NewPolicyEngine(policy *model.IssuancePolicy) (*PolicyEngine, error) {
	if policy == nil {
		return nil, nil
	}

	if len(policy.Rules) == 0 && policy.RulesFile == "" {
		return nil, fmt.Errorf("issuance policy is configured but defines neither rules nor rules_file: " +
			"add rules, or remove the issuance_policy block")
	}

	// A policy with rules must say which dimensions its queries carry.
	//
	// The old alternative - no query_template, one dimension per claim the
	// request happened to return, sorted by name - could not express a
	// policy. SPOCP matches the rule's dimensions against the query's by
	// position, so a rule naming two claims only matches when those two sort
	// ahead of every other claim in the token. A real ID token carries aud,
	// auth_time, iss, nonce and sub whatever else it carries, so the
	// documented example "(credential (scope org_credential)(acr ...)
	// (org_id))" denies against a token that asserts both acr and org_id.
	// Every such policy was a blanket deny that read as a working
	// configuration, so it is refused rather than left advertised.
	//
	// Requiring it also makes rule-shape validation unconditional: dims is
	// now always known, so a rule with the wrong dimensions is caught here
	// rather than never matching at evaluation time.
	if len(policy.QueryTemplate) == 0 {
		return nil, fmt.Errorf("issuance policy defines rules but no query_template: " +
			"rules are matched against query dimensions by position, so the dimensions each rule expects " +
			"must be stated; list them in query_template in the order the rules use them")
	}

	dims := policyRuleDimensions(policy.QueryTemplate)
	engine, err := spocputil.BuildEngine("credential", dims, false, "issuance policy", policy.Rules, policy.RulesFile)
	if err != nil {
		return nil, err
	}
	if engine == nil || engine.RuleCount() == 0 {
		return nil, fmt.Errorf("issuance policy is configured but no rules were loaded "+
			"(rules_file %q is empty or holds only comments): "+
			"an empty rule set denies every issuance for this scope, "+
			"so add rules, or remove the issuance_policy block", policy.RulesFile)
	}

	return &PolicyEngine{engine: engine}, nil
}

// RuleCount reports how many rules this policy loaded. Non-zero for any
// engine NewPolicyEngine returns; exposed for start-up logging.
func (pe *PolicyEngine) RuleCount() int {
	return pe.engine.RuleCount()
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
	// A non-nil policy now always yields either an engine with rules or an
	// error, so there is no "configured but inert" result to pass on.

	actual, _ := engineCache.LoadOrStore(policy, engine)
	return actual.(*PolicyEngine), nil
}

// Evaluate checks if the given claims satisfy the issuance policy for the specified scope.
// Returns nil if authorized, or an error describing why issuance was denied.
func (pe *PolicyEngine) Evaluate(scope string, claims map[string]any, queryTemplate []model.QueryDimension) error {
	// Belt and braces with NewPolicyEngine's check. An engine only exists
	// for a policy that had a template, but Evaluate is handed the template
	// separately by its caller, and a check that cannot decide has to
	// refuse: without dimensions the query would carry only the scope, and
	// whether that matched would say nothing about the claims.
	if len(queryTemplate) == 0 {
		return fmt.Errorf("issuance policy for scope %q was evaluated with no query_template: "+
			"the query would carry no claim dimensions, so it cannot decide anything", scope)
	}

	query, missing := buildQuery(scope, claims, queryTemplate)

	// An absent claim is not a wildcard.
	//
	// An unresolved dimension is emitted empty, as `(org_id)`, and that is
	// also how a wildcard rule is written under this rule set's convention -
	// so SPOCP matched them against each other and `(credential (scope pid)
	// (org_id))`, meaning "any org_id", authorized a token carrying no
	// org_id at all. "Any value" has to mean a value exists, or the weakest
	// rule an operator can write is satisfied by asserting nothing.
	//
	// Denying rather than emitting a sentinel, because an operator who does
	// not care about a dimension already has a way to say so: leave it out
	// of query_template, and it appears in neither the query nor the rule
	// shape. Listing it is a statement that the OP must assert it.
	if len(missing) > 0 {
		return fmt.Errorf("issuance policy denied: scope %q requires claims the provider did not assert: %v",
			scope, missing)
	}

	if !pe.engine.QueryElement(query) {
		return fmt.Errorf("issuance policy denied: claims do not satisfy any rule for scope %q", scope)
	}

	return nil
}

// BuildQuery constructs a SPOCP query S-expression from credential scope and OIDC claims.
// The query has the form: (credential (scope <scope>) (dim1 <value1>) (dim2 <value2>) ...)
//
// The dimensions come from queryTemplate, in its order, so they line up with
// the positions the rules were validated against. There is no longer a
// claim-driven fallback for an absent template: it emitted whatever claims
// the token happened to carry, in name order, which shifted the rule's
// dimensions out of position and denied. See NewPolicyEngine.
func BuildQuery(scope string, claims map[string]any, queryTemplate []model.QueryDimension) sexp.Element {
	query, _ := buildQuery(scope, claims, queryTemplate)

	return query
}

// buildQuery is BuildQuery plus the part a caller must not be able to ignore:
// which template claims the provider did not assert.
//
// They are returned rather than folded into the query because the query cannot
// express the difference. An unresolved dimension is emitted empty, and an
// empty dimension is exactly how a wildcard rule is written here, so absence
// and "any value" become the same S-expression. Evaluate denies on a non-empty
// missing list before querying.
func buildQuery(scope string, claims map[string]any, queryTemplate []model.QueryDimension) (sexp.Element, []string) {
	dims := make([]string, 0, len(queryTemplate)+1)
	dims = append(dims, scopeDimension)
	values := map[string]string{scopeDimension: scope}

	var missing []string
	for _, dim := range queryTemplate {
		dims = append(dims, dim.Dimension)
		value, ok := lookupClaim(claims, dim.Claim)
		if !ok {
			missing = append(missing, dim.Claim)
			continue
		}
		values[dim.Dimension] = toStringValue(value)
	}

	return spocputil.BuildTaggedQuery("credential", dims, values), missing
}

// lookupClaim resolves a query template's claim path against the OIDC claims.
//
// The flat key is tried first, so a claim whose name itself contains a dot
// keeps resolving exactly as it did. Only then is the path walked as
// dot-notation, which is what the configuration documents and what the
// callback actually produces: ProcessCallback fills the map via
// idToken.Claims, so a nested claim arrives as a map under its parent and
// "identity.given_name" is never a key.
//
// Worth its own function because the failure was silent. An unresolved
// dimension is emitted empty, an empty dimension matches a wildcard rule
// and fails a rule that requires a value - so a policy written against the
// documented dot-notation would widen or hard-deny with nothing anywhere
// saying why.
func lookupClaim(claims map[string]any, path string) (any, bool) {
	if value, ok := claims[path]; ok {
		return value, true
	}
	return credential.GetNestedValue(claims, path)
}

// toStringValue renders a claim value as the atom that goes into one query
// dimension.
//
// The composite case has to be deterministic. A claim can legitimately be an
// object or an array (an address, a list of entitlements), and fmt's %v on a
// map iterates in Go's randomised order - so the same claims would render as
// different atoms between two requests, and a rule written against one of
// those spellings would match sometimes and deny sometimes, with nothing in
// the logs distinguishing the runs. json.Marshal sorts object keys, so the
// same value always renders the same way.
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
		encoded, err := json.Marshal(val)
		if err != nil {
			// Nothing reaching here from a decoded ID token is unmarshalable,
			// but a value that cannot be rendered stably must not be rendered
			// unstably: %v at least keeps the dimension populated, and an
			// unmatched rule denies, which is the safe direction.
			return fmt.Sprintf("%v", val)
		}
		return string(encoded)
	}
}
