package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckAuthScopes pins the config-load check: an auth_scopes key naming no
// configured credential used to start the server and fail at request time,
// because the struct-level validation sees only the DataSources stanza.
func TestCheckAuthScopes(t *testing.T) {
	credentialMetadata := map[string]*model.CredentialMetadata{
		"pid":   {Format: "dc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
		"eduid": {Format: "dc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:credential:eduid:1"}},
	}

	cfgWith := func(scopes map[string]model.DatastoreScope) *model.Cfg {
		return &model.Cfg{
			Common: &model.Common{CredentialMetadata: credentialMetadata},
			APIGW: &model.APIGW{
				DataSources: model.DataSources{
					Datastore: model.DatastoreConfig{Scopes: scopes},
				},
			},
		}
	}

	t.Run("every auth scope resolves", func(t *testing.T) {
		err := checkAuthScopes(cfgWith(map[string]model.DatastoreScope{
			"ehic": {
				AuthProvider: model.AuthProviderOpenID4VP,
				AuthScopes: map[string]model.AuthScopeEntry{
					"pid":   {AuthClaims: []string{"given_name"}},
					"eduid": {AuthClaims: []string{"given_name"}},
				},
			},
		}))
		assert.NoError(t, err)
	})

	t.Run("an unknown auth scope is reported with its path", func(t *testing.T) {
		err := checkAuthScopes(cfgWith(map[string]model.DatastoreScope{
			"ehic": {
				AuthProvider: model.AuthProviderOpenID4VP,
				AuthScopes: map[string]model.AuthScopeEntry{
					"pid":              {AuthClaims: []string{"given_name"}},
					"nosuchcredential": {AuthClaims: []string{"given_name"}},
				},
			},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ehic.auth_scopes.nosuchcredential")
		assert.NotContains(t, err.Error(), "ehic.auth_scopes.pid")
	})

	t.Run("every offender is named, in a stable order", func(t *testing.T) {
		err := checkAuthScopes(cfgWith(map[string]model.DatastoreScope{
			"ehic": {
				AuthProvider: model.AuthProviderOpenID4VP,
				AuthScopes: map[string]model.AuthScopeEntry{
					"aaa": {AuthClaims: []string{"given_name"}},
					"zzz": {AuthClaims: []string{"given_name"}},
				},
			},
		}))
		require.Error(t, err)
		// Sorted, so the same config reports the same message every time.
		assert.Regexp(t, `ehic\.auth_scopes\.aaa, ehic\.auth_scopes\.zzz`, err.Error())
	})

	t.Run("only openid4vp scopes are checked", func(t *testing.T) {
		// auth_scopes has no meaning for a SAML/OIDC-authenticated credential,
		// and the struct-level rules already reject it there.
		err := checkAuthScopes(cfgWith(map[string]model.DatastoreScope{
			"ehic": {
				AuthProvider: model.AuthProviderSAML,
				AuthScopes: map[string]model.AuthScopeEntry{
					"nosuchcredential": {AuthClaims: []string{"given_name"}},
				},
			},
		}))
		assert.NoError(t, err)
	})

	t.Run("a service with no apigw stanza has nothing to check", func(t *testing.T) {
		assert.NoError(t, checkAuthScopes(&model.Cfg{Common: &model.Common{}}))
	})

	t.Run("no credential_metadata at all", func(t *testing.T) {
		cfg := cfgWith(map[string]model.DatastoreScope{
			"ehic": {
				AuthProvider: model.AuthProviderOpenID4VP,
				AuthScopes:   map[string]model.AuthScopeEntry{"pid": {AuthClaims: []string{"given_name"}}},
			},
		})
		cfg.Common = nil
		assert.Error(t, checkAuthScopes(cfg), "a config with no credentials cannot satisfy any auth scope")
	})
}
