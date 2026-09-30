package configuration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckPolicyClaimsAreNotCallerTemplated: PAR authenticates the WALLET,
// not the origin of a statement about an organisation, so an authorized
// caller chooses the value this service asks the OP to assert. The OIDC
// claims parameter's "value" member asks for a specific value, and an OP
// that honours it hands the caller's own choice back in the token - where a
// policy gated on that claim reads it as the OP's word. Nothing at request
// time can tell that token from an honest one, so the configuration is
// refused at startup.
func TestCheckPolicyClaimsAreNotCallerTemplated(t *testing.T) {
	cfgWith := func(params *model.OIDCRequestParams, policy *model.IssuancePolicy) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"org_credential": {
					AuthProvider:      model.AuthProviderOIDC,
					OIDCRequestParams: params,
					IssuancePolicy:    policy,
				},
			}},
		}}}
	}

	policyOn := func(claims ...string) *model.IssuancePolicy {
		policy := &model.IssuancePolicy{Rules: []string{"(credential (scope org_credential))"}}
		for _, claim := range claims {
			policy.QueryTemplate = append(policy.QueryTemplate, model.QueryDimension{Dimension: claim, Claim: claim})
		}
		return policy
	}

	const callerFilledOrgID = `{"id_token":{"org_id":{"value":"{{.org_id}}"}}}`

	t.Run("a policy gated on the claim the caller fills is refused", func(t *testing.T) {
		err := checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: callerFilledOrgID}, policyOn("org_id")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "org_id")
		assert.Contains(t, err.Error(), "org_credential")
	})

	t.Run("a policy gated on a different claim is allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: callerFilledOrgID}, policyOn("acr"))),
			"templating a claim the policy does not read is the feature working")
	})

	t.Run("a claim the OPERATOR pins is allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":{"value":"sunet"}}}`}, policyOn("org_id"))),
			"a fixed value is the operator's, not the caller's")
	})

	t.Run("a nested policy claim is matched on its top-level name", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: `{"id_token":{"identity":{"value":"{{.identity}}"}}}`},
			policyOn("identity.given_name"))))
	})

	t.Run("acr_values counts as asking for the acr claim", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{ACRValues: "{{.loa}}"}, policyOn("acr"))))
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{ACRValues: "urn:example:loa3"}, policyOn("acr"))))
	})

	t.Run("userinfo is read too", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: `{"userinfo":{"org_id":{"value":"{{.org_id}}"}}}`},
			policyOn("org_id"))))
	})

	t.Run("a template that cannot render is refused rather than skipped", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":{{.org_id}}}}`}, policyOn("org_id"))),
			"a claims template this cannot read is one it cannot vouch for")
	})

	// resolveTemplate executes the full text/template grammar, so a regexp
	// over "{{.name}}" sees only one of the ways a caller value reaches the
	// request. These all read the same DynamicParams map.
	for name, claims := range map[string]string{
		"index":             `{{index . "org_id"}}`,
		"index with a pipe": `{{index . "org_id" | printf "%s"}}`,
		"a field in a pipe": `{{.org_id | printf "%s"}}`,
		"a variable":        `{{$v := .org_id}}{{$v}}`,
		"an unrelated key":  `{{index . "some_other_param"}}`,
	} {
		t.Run("a caller value reaches the claim through "+name, func(t *testing.T) {
			err := checkPolicyClaimsAreNotCallerTemplated(cfgWith(
				&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":{"value":"` + claims + `"}}}`},
				policyOn("org_id")))
			require.Error(t, err, "%s reads the caller's data", claims)
			assert.Contains(t, err.Error(), "org_id")
		})
	}

	// The forms where the caller decides which BRANCH runs are refused for
	// their own reason, and before the claim is even attributed: such a
	// template need never emit the value to change the request.
	for name, claims := range map[string]string{
		"with":          `{{with .org_id}}{{.}}{{end}}`,
		"if":            `{{if .org_id}}{{.org_id}}{{end}}`,
		"the whole dot": `{{range $k, $v := .}}{{$v}}{{end}}`,
	} {
		t.Run("a caller value drives control flow through "+name, func(t *testing.T) {
			err := checkPolicyClaimsAreNotCallerTemplated(cfgWith(
				&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":{"value":"` + claims + `"}}}`},
				policyOn("org_id")))
			require.Error(t, err, "%s lets the caller choose a branch", claims)
			assert.Contains(t, err.Error(), "which branch of the template runs")
		})
	}

	// The operator's own template text, reading nothing from the caller, is
	// not a caller value - or every configured claims parameter would be
	// refused and the check would be a ban rather than a boundary.
	for name, claims := range map[string]string{
		"a constant action": `{{printf "sunet"}}`,
		"no action at all":  `sunet`,
	} {
		t.Run("a policy claim written by "+name+" is allowed", func(t *testing.T) {
			assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
				&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":{"value":"` + claims + `"}}}`},
				policyOn("org_id"))))
		})
	}

	// An opaque read cannot be attributed to a claim, so every claim the
	// template requests is treated as filled.
	t.Run("an opaque read taints every claim the template requests", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: `{"id_token":{"org_id":null,"dept":{"value":"{{range $k, $v := .}}{{$v}}{{end}}"}}}`},
			policyOn("org_id"))),
			"which claim the value lands in is unknown, so org_id cannot be vouched for")
	})

	t.Run("acr_values reads the caller's data indirectly too", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{ACRValues: `{{index . "loa"}}`}, policyOn("acr"))))
	})

	t.Run("nothing configured is nothing to check", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(&model.Cfg{}))
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(nil, policyOn("org_id"))))
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			&model.OIDCRequestParams{Claims: callerFilledOrgID}, nil)))
	})

	// SAML and pre-authorized scopes never build an authorization request,
	// so there is no template and no OP to ask.
	t.Run("a non-OIDC scope is not this check's business", func(t *testing.T) {
		cfg := cfgWith(&model.OIDCRequestParams{Claims: callerFilledOrgID}, policyOn("org_id"))
		scope := cfg.APIGW.DataSources.Datastore.Scopes["org_credential"]
		scope.AuthProvider = "saml"
		cfg.APIGW.DataSources.Datastore.Scopes["org_credential"] = scope
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfg))
	})
}

// TestClaimsTemplateMustKeepCallerValuesInStrings: resolveJSONTemplate
// escapes each value as JSON string content and then strips the surrounding
// quotes, because the documented form puts the placeholder inside a string.
// Nothing restricted the configuration to that form - written without the
// quotes, the same escaping inserts the caller's text as raw JSON, so a
// value like `true,"essential":true` changes the members of the request and
// still passes the json.Valid check at the end.
func TestClaimsTemplateMustKeepCallerValuesInStrings(t *testing.T) {
	cfgWith := func(claims string, policy *model.IssuancePolicy) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"org_credential": {
					AuthProvider:      model.AuthProviderOIDC,
					OIDCRequestParams: &model.OIDCRequestParams{Claims: claims},
					IssuancePolicy:    policy,
				},
			}},
		}}}
	}

	t.Run("a placeholder inside a string is the documented form", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"org_id":{"value":"{{.org_id}}"}}}`, nil)))
	})

	t.Run("a placeholder outside a string is refused", func(t *testing.T) {
		err := checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"org_id":{"value":{{.org_id}}}}}`, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "change the request's structure")
	})

	t.Run("a placeholder used as an object key is refused", func(t *testing.T) {
		err := checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"{{.claim_name}}":{"essential":true}}}`, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "object KEY")
	})

	// Checked whether or not a policy reads the answer: the structural rule
	// is about what a caller can do to the REQUEST.
	t.Run("a scope with no issuance policy is checked too", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"org_id":{"value":{{.org_id}}}}}`, nil)))
	})

	// The concrete attack the escaping does not stop: the rendered document
	// is valid JSON and has members the operator never wrote.
	t.Run("the injection this refuses really does produce valid JSON", func(t *testing.T) {
		const templated = `{"id_token":{"org_id":{"value":{{.org_id}}}}}`
		injected := strings.ReplaceAll(templated, "{{.org_id}}", `"sunet","essential":true`)
		require.True(t, json.Valid([]byte(injected)),
			"a json.Valid check at the end of substitution cannot see this")

		var parsed map[string]map[string]map[string]any
		require.NoError(t, json.Unmarshal([]byte(injected), &parsed))
		assert.Equal(t, true, parsed["id_token"]["org_id"]["essential"],
			"the caller added a member to the request")
	})
}

// TestClaimsTemplateRefusesCallerDrivenControlFlow: a caller value used as
// CONTROL FLOW need never be emitted to change the request. Rendering once
// with a non-empty sentinel produces valid JSON that does not contain it, so
// a check that looks for the substituted value sees nothing - while at
// runtime the caller still decides whether the member is there.
func TestClaimsTemplateRefusesCallerDrivenControlFlow(t *testing.T) {
	cfgWith := func(claims string, policy *model.IssuancePolicy) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"org_credential": {
					AuthProvider:      model.AuthProviderOIDC,
					OIDCRequestParams: &model.OIDCRequestParams{Claims: claims},
					IssuancePolicy:    policy,
				},
			}},
		}}}
	}

	// The exact shape that slipped through: the sentinel is never emitted,
	// and the rendering is valid JSON with the member present.
	const conditional = `{"id_token":{"org_id":{{if .org_id}}{"value":"anything"}{{else}}null{{end}}}}`

	t.Run("the rendering really does hide it", func(t *testing.T) {
		access, err := analyzeTemplate(conditional)
		require.NoError(t, err)
		rendered, err := renderWithSentinel(conditional, access.keys)
		require.NoError(t, err)
		assert.NotContains(t, rendered, claimSentinel,
			"the sentinel is not emitted, which is why looking for it is not enough")
		assert.True(t, json.Valid([]byte(rendered)), "and the result parses")
	})

	t.Run("it is refused anyway", func(t *testing.T) {
		err := checkPolicyClaimsAreNotCallerTemplated(cfgWith(conditional, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "which branch of the template runs")
	})

	t.Run("control flow that reads nothing from the caller is allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(cfgWith(
			`{"id_token":{"org_id":{{if true}}null{{else}}null{{end}}}}`, nil)))
	})
}

// TestTemplatedCustomParamsAreRefusedOnAPolicyScope: custom_params are
// arbitrary by design, so this service cannot know what an OP does with one
// - and an OP that treats a parameter as a hint about the subject can echo
// it into any claim. There is no claim to name and so no narrow rule to
// write.
func TestTemplatedCustomParamsAreRefusedOnAPolicyScope(t *testing.T) {
	cfgWith := func(custom map[string]string, policy *model.IssuancePolicy) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"org_credential": {
					AuthProvider:      model.AuthProviderOIDC,
					OIDCRequestParams: &model.OIDCRequestParams{CustomParams: custom},
					IssuancePolicy:    policy,
				},
			}},
		}}}
	}
	policy := &model.IssuancePolicy{
		Rules:         []string{"(credential (scope org_credential))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
	}

	t.Run("a templated custom param on a policy scope is refused", func(t *testing.T) {
		err := checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(map[string]string{"org_id": "{{.org_id}}"}, policy))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "custom_params")
	})

	t.Run("the indirect form is refused too", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(map[string]string{"org_id": `{{index . "org_id"}}`}, policy)))
	})

	t.Run("a fixed custom param is the operator's and is allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(map[string]string{"org_id": "sunet"}, policy)))
	})

	t.Run("a templated custom param without a policy is allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(map[string]string{"org_id": "{{.org_id}}"}, nil)))
	})
}

// TestPolicyClaimMatchesBothSpellings: lookupClaim tries the whole dotted
// string as a flat key BEFORE walking the path, so a policy claim
// "identity.given_name" can be satisfied by a literal claim of that name -
// and a check that looked only at the top-level segment accepted a template
// requesting exactly it.
func TestPolicyClaimMatchesBothSpellings(t *testing.T) {
	cfgWith := func(claims string) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"org_credential": {
					AuthProvider:      model.AuthProviderOIDC,
					OIDCRequestParams: &model.OIDCRequestParams{Claims: claims},
					IssuancePolicy: &model.IssuancePolicy{
						Rules:         []string{"(credential (scope org_credential))"},
						QueryTemplate: []model.QueryDimension{{Dimension: "given_name", Claim: "identity.given_name"}},
					},
				},
			}},
		}}}
	}

	t.Run("the dotted claim requested literally", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"identity.given_name":{"value":"{{.name}}"}}}`)))
	})

	t.Run("the same claim requested through its top-level name", func(t *testing.T) {
		require.Error(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"identity":{"value":"{{.name}}"}}}`)))
	})

	t.Run("an unrelated claim is still allowed", func(t *testing.T) {
		assert.NoError(t, checkPolicyClaimsAreNotCallerTemplated(
			cfgWith(`{"id_token":{"department":{"value":"{{.dept}}"}}}`)))
	})
}
