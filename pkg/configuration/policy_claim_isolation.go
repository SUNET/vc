package configuration

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/SUNET/vc/pkg/model"
)

// checkPolicyClaimsAreNotCallerTemplated refuses a scope whose issuance
// policy is gated on a claim the CALLER gets to ask the OP for.
//
// oidc_request_params.claims is filled in from PARRequest.DynamicParams, and
// PAR authenticates the wallet, not the origin of a statement about an
// organisation. So an authorized PAR caller chooses the value this service
// asks the OP to assert. That is documented and bounded - a caller cannot add
// a parameter, reach one the operator did not template, override a reserved
// one, or inject structure into the claims JSON - and issuance is gated on
// what the OP ASSERTED, never on the request.
//
// The gap that leaves is one configuration: a scope whose policy consults
// exactly the claim the caller filled in. The OIDC claims parameter's "value"
// member asks the OP to assert a specific value, and an OP that honours it
// hands the caller's own choice back in the token - where the policy reads it
// as the OP's word. Nothing at request time can tell that token from an
// honest one, so the configuration is refused at startup instead.
//
// Deliberately narrow. Templating a claim the policy does NOT consult stays
// allowed, because that is the feature working: the operator decides which
// parameters exist and where a template may appear, and the answer still has
// to come back in the token.
func checkPolicyClaimsAreNotCallerTemplated(cfg *model.Cfg) error {
	if cfg.APIGW == nil {
		return nil
	}

	type scopeConfig struct {
		source string
		params *model.OIDCRequestParams
		policy *model.IssuancePolicy
	}

	configured := map[string]scopeConfig{}
	add := func(source, scope, provider string, params *model.OIDCRequestParams, policy *model.IssuancePolicy) {
		// OIDC only: there is no authorization request to template
		// otherwise, and no OP to ask.
		if provider != model.AuthProviderOIDC || params == nil || policy == nil {
			return
		}
		configured[source+"."+scope] = scopeConfig{source: source, params: params, policy: policy}
	}
	for scope, s := range cfg.APIGW.DataSources.Datastore.Scopes {
		add("datastore", scope, s.AuthProvider, s.OIDCRequestParams, s.IssuancePolicy)
	}
	for scope, s := range cfg.APIGW.DataSources.Assertion.Scopes {
		add("assertion", scope, s.AuthProvider, s.OIDCRequestParams, s.IssuancePolicy)
	}
	for scope, s := range cfg.APIGW.DataSources.ExternalAPI.Scopes {
		add("external_api", scope, s.AuthProvider, s.OIDCRequestParams, s.IssuancePolicy)
	}

	var problems []string
	for _, key := range slices.Sorted(maps.Keys(configured)) {
		entry := configured[key]
		filled, err := claimsFilledByCaller(entry.params)
		if err != nil {
			return fmt.Errorf("apigw.data_sources.%s.scopes.%s: oidc_request_params could not be checked against the issuance policy: %w",
				entry.source, strings.SplitN(key, ".", 2)[1], err)
		}
		for _, dimension := range entry.policy.QueryTemplate {
			// Nested claims are addressed in dot-notation, and the claims
			// request parameter names the top-level claim.
			claim := strings.SplitN(dimension.Claim, ".", 2)[0]
			if !filled[claim] {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"apigw.data_sources.%s.scopes.%s: issuance_policy.query_template reads claim %q, which oidc_request_params lets the caller ask the OP to assert",
				entry.source, strings.SplitN(key, ".", 2)[1], dimension.Claim))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s - an OP that honours the request would hand the caller's own value back as its word; template a claim the policy does not read, or drop the template", strings.Join(problems, "; "))
	}

	return nil
}

// templatePlaceholder matches the dynamic values a caller supplies. Only the
// simple ".name" form is a caller value; anything else is the operator's own
// template text and cannot be filled from DynamicParams.
var templatePlaceholder = regexp.MustCompile(`{{\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*}}`)

// claimsFilledByCaller reports which requested claim names carry a
// caller-supplied value.
//
// Rendered rather than pattern-matched: the claims parameter is JSON with a
// documented shape (OIDC Core 5.5), and which CLAIM a placeholder lands in is
// a structural question. Rendering each placeholder to a unique sentinel and
// then reading the JSON answers it exactly, and fails loudly on a template
// that does not render or does not produce JSON - which is the same refusal
// the request path makes.
func claimsFilledByCaller(params *model.OIDCRequestParams) (map[string]bool, error) {
	filled := map[string]bool{}

	// acr_values does not go through the claims parameter, but it asks the
	// OP for an authentication context and comes back as the acr claim.
	if templatePlaceholder.MatchString(params.ACRValues) {
		filled["acr"] = true
	}

	if params.Claims == "" {
		return filled, nil
	}

	const sentinel = "caller-supplied-value-sentinel"
	values := map[string]string{}
	for _, match := range templatePlaceholder.FindAllStringSubmatch(params.Claims, -1) {
		values[match[1]] = sentinel
	}
	if len(values) == 0 {
		return filled, nil
	}

	tmpl, err := template.New("claims").Option("missingkey=error").Parse(params.Claims)
	if err != nil {
		return nil, fmt.Errorf("claims is not a valid template: %w", err)
	}
	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, values); err != nil {
		return nil, fmt.Errorf("claims template could not be rendered: %w", err)
	}

	var requested map[string]any
	if err := json.Unmarshal([]byte(rendered.String()), &requested); err != nil {
		return nil, fmt.Errorf("claims does not render to a JSON object: %w", err)
	}

	// OIDC Core 5.5: the top-level members are the token the claims are
	// requested in, and each key under one of those is a claim name.
	for _, target := range []string{"id_token", "userinfo"} {
		claims, ok := requested[target].(map[string]any)
		if !ok {
			continue
		}
		for claim, constraint := range claims {
			if containsSentinel(constraint, sentinel) {
				filled[claim] = true
			}
		}
	}

	return filled, nil
}

// containsSentinel reports whether a rendered claim constraint carries a
// caller-supplied value anywhere inside it - "value", "values", or any other
// member the operator wrote the placeholder into.
func containsSentinel(node any, sentinel string) bool {
	switch typed := node.(type) {
	case string:
		return strings.Contains(typed, sentinel)
	case []any:
		return slices.ContainsFunc(typed, func(item any) bool { return containsSentinel(item, sentinel) })
	case map[string]any:
		for _, item := range typed {
			if containsSentinel(item, sentinel) {
				return true
			}
		}
	}
	return false
}
