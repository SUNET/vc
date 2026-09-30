package configuration

import (
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
		"with":              `{{with .org_id}}{{.}}{{end}}`,
		"if":                `{{if .org_id}}{{.org_id}}{{end}}`,
		"a variable":        `{{$v := .org_id}}{{$v}}`,
		"the whole dot":     `{{range $k, $v := .}}{{$v}}{{end}}`,
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
