package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/template"
	"text/template/parse"

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
		// Params alone is enough to be worth checking: the structural rule
		// below is about what a caller can do to the REQUEST, whether or
		// not a policy reads the answer.
		if provider != model.AuthProviderOIDC || params == nil {
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
		scope := strings.SplitN(key, ".", 2)[1]

		if err := checkClaimsTemplateIsStructural(entry.params.Claims); err != nil {
			return fmt.Errorf("apigw.data_sources.%s.scopes.%s: oidc_request_params.claims %w", entry.source, scope, err)
		}

		if entry.policy == nil {
			continue
		}

		filled, err := claimsFilledByCaller(entry.params)
		if err != nil {
			return fmt.Errorf("apigw.data_sources.%s.scopes.%s: oidc_request_params could not be checked against the issuance policy: %w",
				entry.source, strings.SplitN(key, ".", 2)[1], err)
		}
		for _, dimension := range entry.policy.QueryTemplate {
			// BOTH spellings, because lookupClaim reads both. It tries the
			// whole dotted string as a flat key first and only then walks
			// the path, so a policy claim "identity.given_name" can be
			// satisfied either by a literal claim of that name or by a
			// nested one under "identity" - and a requested claim of either
			// shape carries the caller's value into it.
			claim := dimension.Claim
			topLevel := strings.SplitN(claim, ".", 2)[0]
			if !filled[claim] && !filled[topLevel] {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"apigw.data_sources.%s.scopes.%s: issuance_policy.query_template reads claim %q, which oidc_request_params lets the caller ask the OP to assert",
				entry.source, strings.SplitN(key, ".", 2)[1], dimension.Claim))
		}
		// custom_params are arbitrary by design: this service cannot know
		// what an OP does with one, and an OP that treats a parameter as a
		// hint about the subject can echo it into any claim. There is no
		// claim to name and so no narrow rule to write, which leaves the
		// choice between allowing an unbounded caller-controlled input into
		// a scope whose issuance is gated on OP claims, and refusing the
		// combination. It is refused.
		for _, name := range slices.Sorted(maps.Keys(entry.params.CustomParams)) {
			access, err := analyzeTemplate(entry.params.CustomParams[name])
			if err != nil {
				return fmt.Errorf("apigw.data_sources.%s.scopes.%s: custom_params %q could not be checked against the issuance policy: %w",
					entry.source, strings.SplitN(key, ".", 2)[1], name, err)
			}
			if len(access.keys) == 0 && !access.opaque {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"apigw.data_sources.%s.scopes.%s: custom_params %q is filled in by the caller, and this scope's issuance is gated on claims the OP returns",
				entry.source, strings.SplitN(key, ".", 2)[1], name))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s - an OP that honours the request would hand the caller's own value back as its word; template a claim the policy does not read, or drop the template", strings.Join(problems, "; "))
	}

	return nil
}

// checkClaimsTemplateIsStructural refuses a claims template whose caller
// values could change the request's SHAPE rather than fill a value in it.
//
// resolveJSONTemplate escapes each value as JSON string content and then
// strips the surrounding quotes, because the documented form puts the
// placeholder inside a string:
//
//	{"id_token":{"org_id":{"value":"{{.org_id}}"}}}
//
// Nothing restricted the configuration to that form. Written without the
// quotes the same escaping inserts the caller's text as raw JSON, so a value
// like `true,"essential":true` changes the members of the request and still
// passes the json.Valid check at the end. A placeholder used as an object
// KEY is the same defect in the other direction: the caller then chooses
// which claim is requested.
//
// Checked by rendering: a sentinel outside a string literal is not valid
// JSON, and a sentinel in a key is visible in the parsed object. Both are
// refused at startup, which is where an operator can still fix them.
func checkClaimsTemplateIsStructural(claims string) error {
	if claims == "" {
		return nil
	}

	access, err := analyzeTemplate(claims)
	if err != nil {
		return fmt.Errorf("is not a valid template: %w", err)
	}
	if len(access.keys) == 0 && !access.opaque {
		return nil
	}

	rendered, err := renderWithSentinel(claims, access.keys)
	if err != nil {
		return err
	}

	var requested any
	if err := json.Unmarshal([]byte(rendered), &requested); err != nil {
		return fmt.Errorf("does not render to JSON when a caller value is substituted (%w) - a placeholder outside a JSON string lets the caller's value change the request's structure; write it inside the string, as \"value\": \"{{.name}}\"", err)
	}
	if sentinelInAnyKey(requested) {
		return errors.New("uses a caller value as an object KEY, which lets the caller choose which claim is requested")
	}

	return nil
}

// renderWithSentinel executes a configured template with a recognisable
// value for every key it reads.
func renderWithSentinel(tmplStr string, keys map[string]bool) (string, error) {
	values := make(map[string]string, len(keys))
	for key := range keys {
		values[key] = claimSentinel
	}

	tmpl, err := template.New("render").Option("missingkey=error").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("is not a valid template: %w", err)
	}
	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, values); err != nil {
		return "", fmt.Errorf("could not be rendered: %w", err)
	}

	return rendered.String(), nil
}

// claimSentinel is a value no JSON literal can be mistaken for, so a
// placeholder written outside a string leaves the rendered document
// unparseable rather than merely different.
const claimSentinel = "caller-supplied-value-sentinel"

// sentinelInAnyKey reports whether a caller value ended up naming a member
// rather than filling one.
func sentinelInAnyKey(node any) bool {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			if strings.Contains(key, claimSentinel) || sentinelInAnyKey(value) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(typed, sentinelInAnyKey)
	}
	return false
}

// templateAccess describes what a configured template reads from the
// caller's data.
//
// Parsed, not pattern-matched. resolveTemplate executes the full
// text/template grammar, so "{{index . \"org_id\"}}" renders the caller's
// org_id just as "{{.org_id}}" does, and a regexp over the source text sees
// only the second. Reading the parse tree is the only way to be looking at
// the same language the request path executes.
type templateAccess struct {
	// keys are the caller-supplied names this template reads, where that
	// could be determined.
	keys map[string]bool
	// opaque is true when the template reads from the caller's data in a
	// way this cannot attribute to a name. Then every claim the template
	// writes is treated as caller-filled: the analysis cannot say which one
	// the value lands in, and "cannot tell" has to mean the strict answer.
	opaque bool
}

// analyzeTemplate reads a configured template and reports what it takes from
// the caller.
func analyzeTemplate(tmplStr string) (templateAccess, error) {
	access := templateAccess{keys: map[string]bool{}}
	if tmplStr == "" {
		return access, nil
	}

	// missingkey=error to match resolveTemplate: a template this cannot
	// parse is one the request path cannot execute either.
	tmpl, err := template.New("analysis").Option("missingkey=error").Parse(tmplStr)
	if err != nil {
		return access, fmt.Errorf("not a valid template: %w", err)
	}
	if tmpl.Tree == nil || tmpl.Tree.Root == nil {
		return access, nil
	}
	walkTemplateNode(tmpl.Tree.Root, &access)

	return access, nil
}

// walkTemplateNode records every read of the caller's data in one node.
//
// The two forms an operator is documented to write - "{{.name}}" and
// "{{index . \"name\"}}" - are attributed to a name. Anything else that
// touches the dot at all is recorded as opaque rather than ignored, because
// what it reads is the same caller-supplied map.
func walkTemplateNode(node parse.Node, access *templateAccess) {
	switch typed := node.(type) {
	case *parse.ListNode:
		if typed == nil {
			return
		}
		for _, child := range typed.Nodes {
			walkTemplateNode(child, access)
		}
	case *parse.ActionNode:
		walkPipe(typed.Pipe, access)
	case *parse.IfNode:
		walkBranch(&typed.BranchNode, access)
	case *parse.RangeNode:
		walkBranch(&typed.BranchNode, access)
	case *parse.WithNode:
		walkBranch(&typed.BranchNode, access)
	case *parse.TemplateNode:
		// A nested template is handed the same data and this does not have
		// its body, so what it reads cannot be attributed.
		access.opaque = true
		walkPipe(typed.Pipe, access)
	}
}

func walkBranch(branch *parse.BranchNode, access *templateAccess) {
	walkPipe(branch.Pipe, access)
	walkTemplateNode(branch.List, access)
	walkTemplateNode(branch.ElseList, access)
}

func walkPipe(pipe *parse.PipeNode, access *templateAccess) {
	if pipe == nil {
		return
	}
	for _, cmd := range pipe.Cmds {
		walkCommand(cmd, access)
	}
}

func walkCommand(cmd *parse.CommandNode, access *templateAccess) {
	if cmd == nil || len(cmd.Args) == 0 {
		return
	}

	// "{{index . \"name\"}}" - the documented indirect form.
	if ident, ok := cmd.Args[0].(*parse.IdentifierNode); ok && ident.Ident == "index" && len(cmd.Args) == 3 {
		_, onDot := cmd.Args[1].(*parse.DotNode)
		key, isString := cmd.Args[2].(*parse.StringNode)
		if onDot && isString {
			access.keys[key.Text] = true
			return
		}
	}

	for _, arg := range cmd.Args {
		switch typed := arg.(type) {
		case *parse.FieldNode:
			// "{{.name}}" and "{{.a.b}}"; the caller's data is a flat map,
			// so the first identifier is the key it reads.
			if len(typed.Ident) > 0 {
				access.keys[typed.Ident[0]] = true
			}
			if len(typed.Ident) != 1 {
				access.opaque = true
			}
		case *parse.DotNode, *parse.VariableNode:
			// The whole map, or something bound from it.
			access.opaque = true
		case *parse.PipeNode:
			walkPipe(typed, access)
		}
	}
}

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
	acrAccess, err := analyzeTemplate(params.ACRValues)
	if err != nil {
		return nil, fmt.Errorf("acr_values is not a valid template: %w", err)
	}
	if len(acrAccess.keys) > 0 || acrAccess.opaque {
		filled["acr"] = true
	}

	if params.Claims == "" {
		return filled, nil
	}

	claimsAccess, err := analyzeTemplate(params.Claims)
	if err != nil {
		return nil, fmt.Errorf("claims is not a valid template: %w", err)
	}
	if len(claimsAccess.keys) == 0 && !claimsAccess.opaque {
		return filled, nil
	}

	rendered, err := renderWithSentinel(params.Claims, claimsAccess.keys)
	if err != nil {
		return nil, fmt.Errorf("claims %w", err)
	}

	var requested map[string]any
	if err := json.Unmarshal([]byte(rendered), &requested); err != nil {
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
			// An OPAQUE template reads the caller's data in a way this
			// cannot attribute to a name, so which claim the value lands in
			// is unknown and every claim it requests is treated as filled.
			if claimsAccess.opaque || containsSentinel(constraint, claimSentinel) {
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
