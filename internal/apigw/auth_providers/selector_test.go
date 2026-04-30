package authproviders

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelect(t *testing.T) {
	tests := []struct {
		name       string
		selector   *Selector
		scope      string
		ds         *model.DataSources
		wantAuth   string
		wantSource model.DataSourceType
		wantRemote string
		wantErr    bool
	}{
		{
			name:     "basic always available",
			selector: NewSelector(false, false),
			scope:    "pid",
			ds: &model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {AuthProvider: model.AuthProviderBasic},
				}},
			},
			wantAuth:   model.AuthProviderBasic,
			wantSource: model.DataSourceDatastore,
		},
		{
			name:     "openid4vp always available",
			selector: NewSelector(false, false),
			scope:    "ehic",
			ds: &model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"ehic": {AuthProvider: model.AuthProviderOpenID4VP},
				}},
			},
			wantAuth:   model.AuthProviderOpenID4VP,
			wantSource: model.DataSourceDatastore,
		},
		{
			name:     "saml enabled - selected",
			selector: NewSelector(true, false),
			scope:    "pid",
			ds: &model.DataSources{
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"pid": {AuthProvider: model.AuthProviderSAML},
				}},
			},
			wantAuth:   model.AuthProviderSAML,
			wantSource: model.DataSourceAssertion,
		},
		{
			name:     "saml disabled - skipped, falls back to basic in datastore",
			selector: NewSelector(false, false),
			scope:    "pid",
			ds: &model.DataSources{
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"pid": {AuthProvider: model.AuthProviderSAML},
				}},
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {AuthProvider: model.AuthProviderBasic},
				}},
			},
			wantAuth:   model.AuthProviderBasic,
			wantSource: model.DataSourceDatastore,
		},
		{
			name:     "oidc enabled - selected from external_api",
			selector: NewSelector(false, true),
			scope:    "diploma",
			ds: &model.DataSources{
				ExternalAPI: model.ExternalAPIConfig{Scopes: map[string]model.ExternalAPIScope{
					"diploma": {Remote: "ladok", AuthProvider: model.AuthProviderOIDC},
				}},
			},
			wantAuth:   model.AuthProviderOIDC,
			wantSource: model.DataSourceExternalAPI,
			wantRemote: "ladok",
		},
		{
			name:     "scope not found - error",
			selector: NewSelector(true, true),
			scope:    "unknown",
			ds: &model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {AuthProvider: model.AuthProviderBasic},
				}},
			},
			wantErr: true,
		},
		{
			name:     "provider disabled - error",
			selector: NewSelector(false, false),
			scope:    "pid",
			ds: &model.DataSources{
				Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
					"pid": {AuthProvider: model.AuthProviderSAML},
				}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authProvider, src, err := tt.selector.Select(tt.scope, tt.ds)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAuth, authProvider)
			assert.Equal(t, tt.wantSource, src.DataSource)
			if tt.wantRemote != "" {
				assert.Equal(t, tt.wantRemote, src.RemoteName)
			}
		})
	}
}
