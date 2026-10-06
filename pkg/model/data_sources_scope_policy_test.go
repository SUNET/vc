package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookupScopePolicyConfigIsProviderAware pins that the data source
// answering a policy lookup is the one belonging to the provider the flow
// actually authenticated with.
//
// One credential scope may legitimately be configured in several data sources
// under different auth providers - that is what ResolveDataSource exists to
// disambiguate. The lookup used to return the first data source listing the
// scope, in a fixed assertion/datastore/external_api order, with no regard for
// the provider. An OIDC flow could therefore be handed the settings belonging
// to that scope's SAML or pre-authorized configuration, or find nothing where
// the OIDC entry had a policy - and skipping a configured gate is the failure
// that matters here, not merely reading the wrong acr_values.
func TestLookupScopePolicyConfigIsProviderAware(t *testing.T) {
	oidcPolicy := &IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(acr loa3))"},
		QueryTemplate: []QueryDimension{{Dimension: "acr", Claim: "acr"}},
	}

	// "pid" lives in two data sources. The assertion entry is the SAML one,
	// and it is the one the old lookup order reached first.
	ds := &DataSources{
		Assertion: AssertionConfig{Scopes: map[string]AssertionScope{
			"pid": {AuthProvider: AuthProviderSAML},
		}},
		Datastore: DatastoreConfig{Scopes: map[string]DatastoreScope{
			"pid": {AuthProvider: AuthProviderOIDC, IssuancePolicy: oidcPolicy},
		}},
	}

	t.Run("the oidc entry answers an oidc lookup", func(t *testing.T) {
		got := ds.LookupScopePolicyConfig("pid", AuthProviderOIDC)
		require.NotNil(t, got, "the datastore entry is the scope's oidc configuration")
		assert.Same(t, oidcPolicy, got.IssuancePolicy,
			"an oidc flow must get the oidc entry's policy, not whichever data source listed the scope first")
	})

	t.Run("the saml entry answers a saml lookup", func(t *testing.T) {
		got := ds.LookupScopePolicyConfig("pid", AuthProviderSAML)
		require.NotNil(t, got)
		assert.Nil(t, got.IssuancePolicy, "the saml entry has no policy of its own")
	})

	t.Run("a provider with no entry gets nothing", func(t *testing.T) {
		assert.Nil(t, ds.LookupScopePolicyConfig("pid", AuthProviderOpenID4VP))
	})

	t.Run("an unconfigured scope gets nothing", func(t *testing.T) {
		assert.Nil(t, ds.LookupScopePolicyConfig("diploma", AuthProviderOIDC))
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilDS *DataSources
		assert.Nil(t, nilDS.LookupScopePolicyConfig("pid", AuthProviderOIDC))
	})
}
