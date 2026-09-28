package helpers

import (
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/go-playground/validator/v10"
)

// TestIssuancePolicyQueryTemplate pins the reserved and duplicate dimension
// rules. Both produce a rule shape no rule can match, which presents as a
// blanket issuance deny with nothing in the config looking wrong.
func TestIssuancePolicyQueryTemplate(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	dim := func(d, c string) model.QueryDimension { return model.QueryDimension{Dimension: d, Claim: c} }

	for _, tc := range []struct {
		name    string
		tmpl    []model.QueryDimension
		wantTag string
	}{
		{
			name:    "scope is reserved and auto-populated",
			tmpl:    []model.QueryDimension{dim("scope", "sub"), dim("acr", "acr")},
			wantTag: "query_template_scope_is_reserved",
		},
		{
			name:    "a repeated dimension is rejected",
			tmpl:    []model.QueryDimension{dim("acr", "acr"), dim("acr", "amr")},
			wantTag: "query_template_duplicate_dimension",
		},
		{
			name:    "an empty dimension name is rejected",
			tmpl:    []model.QueryDimension{dim("", "acr")},
			wantTag: "required",
		},
		{
			name:    "a dimension with no claim is rejected",
			tmpl:    []model.QueryDimension{dim("acr", "")},
			wantTag: "required",
		},
		{
			name: "a well-formed template is accepted",
			tmpl: []model.QueryDimension{dim("acr", "acr"), dim("org_id", "organization_id")},
		},
		{
			name:    "a dimension name with whitespace is rejected",
			tmpl:    []model.QueryDimension{dim(" scope", "sub")},
			wantTag: "spocp_dimension",
		},
		{
			name:    "a dimension name with punctuation is rejected",
			tmpl:    []model.QueryDimension{dim("org.id", "organization_id")},
			wantTag: "spocp_dimension",
		},
		{
			// No rules, so there is nothing for a template to line up with.
			name: "an absent template on a policy with no rules is accepted",
			tmpl: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(model.IssuancePolicy{QueryTemplate: tc.tmpl})
			if tc.wantTag == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("expected validation errors, got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == tc.wantTag {
					return
				}
			}
			t.Fatalf("expected a %q failure, got: %v", tc.wantTag, err)
		})
	}
}

// TestIssuancePolicyRequiresQueryTemplate pins the refusal of the claim-driven
// fallback.
//
// SPOCP matches a rule's dimensions against the query's by position. Without a
// template the query was built from whatever claims the token returned, sorted
// by name, so a rule naming two claims matched only when those two sorted
// ahead of every other claim present - and a real ID token always carries aud,
// iss, nonce and sub. Every such policy was a blanket deny that read as a
// working configuration.
func TestIssuancePolicyRequiresQueryTemplate(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		policy     model.IssuancePolicy
		wantReject bool
	}{
		{
			name:       "inline rules with no template",
			policy:     model.IssuancePolicy{Rules: []string{"(credential (scope pid)(acr loa3))"}},
			wantReject: true,
		},
		{
			name:       "rules_file with no template",
			policy:     model.IssuancePolicy{RulesFile: "/etc/vc/issuance.spocp"},
			wantReject: true,
		},
		{
			name: "rules with a template",
			policy: model.IssuancePolicy{
				Rules:         []string{"(credential (scope pid)(acr loa3))"},
				QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.policy)
			if tc.wantReject {
				var verrs validator.ValidationErrors
				if !errors.As(err, &verrs) {
					t.Fatalf("expected validation errors, got %T: %v", err, err)
				}
				for _, ve := range verrs {
					if ve.Tag() == "query_template_required_with_rules" {
						return
					}
				}
				t.Fatalf("expected a query_template_required_with_rules failure, got: %v", err)
			}
			if err != nil {
				t.Fatalf("expected acceptance, got: %v", err)
			}
		})
	}
}

// TestScopeMapsAreValidated pins that per-scope configuration is validated at
// all.
//
// validator does not descend into map values without a dive tag, and the three
// scope maps had none - so every `validate` tag on DatastoreScope,
// AssertionScope and ExternalAPIScope, and the struct-level checks registered
// for IssuancePolicy, were dead for any scope written in a real config file.
// An entry naming a dimension with no claim started cleanly, emitted an empty
// dimension, and satisfied a wildcard rule as though the claim had been
// present.
func TestScopeMapsAreValidated(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	badPolicy := &model.IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(acr))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: ""}},
	}

	for _, tc := range []struct {
		name string
		ds   model.DataSources
	}{
		{
			name: "datastore scope",
			ds: model.DataSources{Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
				"pid": {AuthProvider: "oidc", IssuancePolicy: badPolicy},
			}}},
		},
		{
			name: "assertion scope",
			ds: model.DataSources{Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
				"pid": {AuthProvider: "oidc", IssuancePolicy: badPolicy},
			}}},
		},
		{
			name: "external_api scope",
			ds: model.DataSources{ExternalAPI: model.ExternalAPIConfig{Scopes: map[string]model.ExternalAPIScope{
				"pid": {Remote: "ladok", AuthProvider: "oidc", IssuancePolicy: badPolicy},
			}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.ds)
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("a query dimension with no claim must be rejected through the scope map; got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == "required" {
					return
				}
			}
			t.Fatalf("expected a required failure on the empty claim, got: %v", err)
		})
	}

	t.Run("a well-formed scope map is accepted", func(t *testing.T) {
		ds := model.DataSources{Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
			"pid": {AuthProvider: "oidc", IssuancePolicy: &model.IssuancePolicy{
				Rules:         []string{"(credential (scope pid)(acr loa3))"},
				QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
			}},
		}}}
		if err := v.Struct(ds); err != nil {
			t.Fatalf("expected acceptance, got: %v", err)
		}
	})
}

// TestOIDCOnlyScopeFieldsRejected pins that the two settings only the OIDC
// path reads cannot be attached to a scope authenticated some other way.
//
// issuance_policy is evaluated in the OIDC callback and nowhere else. On a
// saml, openid4vp or preauth scope it used to validate, start, and then be
// skipped for every issuance - which for a security control is the worst
// available outcome: the deployment reads as gated and is not, with nothing
// anywhere saying so.
func TestOIDCOnlyScopeFieldsRejected(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	policy := &model.IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(acr loa3))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
	}
	params := &model.OIDCRequestParams{ACRValues: "urn:example:loa3"}

	for _, tc := range []struct {
		name       string
		value      any
		wantReject bool
	}{
		{"datastore preauth with a policy", model.DatastoreScope{AuthProvider: "preauth", IssuancePolicy: policy}, true},
		{"datastore saml with a policy", model.DatastoreScope{AuthProvider: "saml", IssuancePolicy: policy}, true},
		{"datastore openid4vp with request params", model.DatastoreScope{AuthProvider: "openid4vp", OIDCRequestParams: params}, true},
		{"datastore oidc with a policy", model.DatastoreScope{AuthProvider: "oidc", IssuancePolicy: policy}, false},
		{"assertion saml with a policy", model.AssertionScope{AuthProvider: "saml", IssuancePolicy: policy}, true},
		{"assertion saml with request params", model.AssertionScope{AuthProvider: "saml", OIDCRequestParams: params}, true},
		{"assertion oidc with a policy", model.AssertionScope{AuthProvider: "oidc", IssuancePolicy: policy}, false},
		{"external_api saml with a policy", model.ExternalAPIScope{Remote: "ladok", AuthProvider: "saml", IssuancePolicy: policy}, true},
		{"external_api oidc with a policy", model.ExternalAPIScope{Remote: "ladok", AuthProvider: "oidc", IssuancePolicy: policy}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.value)
			if !tc.wantReject {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("expected validation errors, got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == "oidc_only_scope_field" {
					return
				}
			}
			t.Fatalf("expected an oidc_only_scope_field failure, got: %v", err)
		})
	}
}

// TestScopeProviderUniqueness pins that one scope cannot be configured under
// the same auth_provider in two data sources.
//
// A scope in several data sources is legitimate when the providers differ -
// ResolveDataSource exists to pick between them. With the same provider twice
// there is nothing to pick with, and two readers choose independently:
// LookupCredentialSources (used by ResolveDataSource and the auth provider
// Selector) scans datastore/assertion/external_api, and LookupScopePolicyConfig
// scans for the policy and OIDC request parameters. Those two orders disagreed,
// so a credential could be issued from one entry while the gate governing it
// was read off another. Aligning the orders makes them agree; refusing the
// configuration means the order decides nothing at all.
func TestScopeProviderUniqueness(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	oidcDatastore := map[string]model.DatastoreScope{
		"pid": {AuthProvider: model.AuthProviderOIDC, AuthClaims: []string{"given_name"}},
	}

	for _, tc := range []struct {
		name       string
		ds         model.DataSources
		wantReject bool
	}{
		{
			name: "same scope and provider in datastore and assertion",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: oidcDatastore},
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"pid": {AuthProvider: model.AuthProviderOIDC},
				}},
			},
			wantReject: true,
		},
		{
			name: "same scope and provider in datastore and external_api",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: oidcDatastore},
				ExternalAPI: model.ExternalAPIConfig{Scopes: map[string]model.ExternalAPIScope{
					"pid": {Remote: "ladok", AuthProvider: model.AuthProviderOIDC},
				}},
			},
			wantReject: true,
		},
		{
			// The documented, legitimate case: one scope, two data sources,
			// told apart by the provider the flow authenticated with.
			name: "same scope, different providers",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: oidcDatastore},
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"pid": {AuthProvider: model.AuthProviderSAML},
				}},
			},
		},
		{
			name: "different scopes, same provider",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: oidcDatastore},
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"diploma": {AuthProvider: model.AuthProviderOIDC},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.ds)
			if !tc.wantReject {
				var verrs validator.ValidationErrors
				if errors.As(err, &verrs) {
					for _, ve := range verrs {
						if ve.Tag() == "scope_provider_not_unique" {
							t.Fatalf("expected acceptance, got: %v", err)
						}
					}
				}

				return
			}
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("expected validation errors, got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == "scope_provider_not_unique" {
					return
				}
			}
			t.Fatalf("expected a scope_provider_not_unique failure, got: %v", err)
		})
	}
}

// TestLookupScopePolicyConfigMatchesSourceResolution pins that the helper and
// the data-source resolution agree on which entry wins.
func TestLookupScopePolicyConfigMatchesSourceResolution(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(acr loa3))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
	}

	// The configuration the uniqueness rule now refuses, constructed directly
	// so the two lookups can still be compared: if they ever diverge again,
	// this says so without waiting for a deployment to hit it.
	ds := &model.DataSources{
		Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
			"pid": {AuthProvider: model.AuthProviderOIDC, IssuancePolicy: policy},
		}},
		Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
			"pid": {AuthProvider: model.AuthProviderOIDC},
		}},
	}

	src, err := ds.ResolveDataSource("pid", model.AuthProviderOIDC)
	if err != nil {
		t.Fatal(err)
	}
	if src.DataSource != model.DataSourceDatastore {
		t.Fatalf("resolution picked %q; this test's premise has moved", src.DataSource)
	}

	got := ds.LookupScopePolicyConfig("pid", model.AuthProviderOIDC)
	if got == nil || got.IssuancePolicy != policy {
		t.Fatalf("the policy lookup must answer from the same data source the flow is issued from (%q), got %+v",
			src.DataSource, got)
	}
}
