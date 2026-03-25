package helpers

import (
	"testing"
	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOIDCRPConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      model.OIDCRPConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled config is valid",
			config: model.OIDCRPConfig{
				Enable: false,
			},
			expectError: false,
		},
		{
			name: "valid config with static credentials",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						ClientID:     "test-client",
						ClientSecret: "test-secret",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid", "profile"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "valid config with dynamic registration",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Dynamic: &model.OIDCRPDynamicRegistrationConfig{},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "valid config with default scopes",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						ClientID:     "test-client",
						ClientSecret: "test-secret",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
				// Scopes nil — defaults applied below
			},
			expectError: false,
		},
		{
			name: "missing openid scope",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						ClientID:     "test-client",
						ClientSecret: "test-secret",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"profile", "email"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "oidc_openid_scope_required",
		},
		{
			name: "no registration configured",
			config: model.OIDCRPConfig{
				Enable:            true,
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "required_if",
		},
		{
			name: "both preconfigured and dynamic registration",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						ClientID:     "test-client",
						ClientSecret: "test-secret",
					},
					Dynamic: &model.OIDCRPDynamicRegistrationConfig{},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "excluded_with",
		},
		{
			name: "both preconfigured and dynamic with initial access token",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						ClientID:     "test-client",
						ClientSecret: "test-secret",
					},
					Dynamic: &model.OIDCRPDynamicRegistrationConfig{
						InitialAccessToken: "some-token",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "excluded_with",
		},
		{
			name: "dynamic with initial access token is valid",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Dynamic: &model.OIDCRPDynamicRegistrationConfig{
						InitialAccessToken: "some-token",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "preconfigured missing client_id",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						Enable:      true,
						ClientSecret: "test-secret",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "ClientID",
		},
		{
			name: "preconfigured missing client_secret",
			config: model.OIDCRPConfig{
				Enable: true,
				Registration: &model.OIDCRPRegistrationConfig{
					Preconfigured: &model.OIDCRPPreconfiguredConfig{
						Enable:  true,
						ClientID: "test-client",
					},
				},
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "ClientSecret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := defaults.Set(&tt.config)
			require.NoError(t, err)

			err = CheckSimple(tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateOIDCRPRegistrationExclusion(t *testing.T) {
	t.Run("excluded_with reports errors on both fields", func(t *testing.T) {
		cfg := model.OIDCRPConfig{
			Enable: true,
			Registration: &model.OIDCRPRegistrationConfig{
				Preconfigured: &model.OIDCRPPreconfiguredConfig{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
				},
				Dynamic: &model.OIDCRPDynamicRegistrationConfig{},
			},
			RedirectURI:        "https://example.com/callback",
			IssuerURL:          "https://issuer.example.com",
			Scopes:             []string{"openid"},
			CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
		}
		require.NoError(t, defaults.Set(&cfg))

		err := CheckSimple(cfg)
		require.Error(t, err)

		errStr := err.Error()
		assert.Contains(t, errStr, "Preconfigured")
		assert.Contains(t, errStr, "Dynamic")
		assert.Contains(t, errStr, "excluded_with")
	})

	t.Run("only preconfigured does not trigger exclusion", func(t *testing.T) {
		cfg := model.OIDCRPConfig{
			Enable: true,
			Registration: &model.OIDCRPRegistrationConfig{
				Preconfigured: &model.OIDCRPPreconfiguredConfig{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
				},
			},
			RedirectURI:        "https://example.com/callback",
			IssuerURL:          "https://issuer.example.com",
			Scopes:             []string{"openid"},
			CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
		}
		require.NoError(t, defaults.Set(&cfg))

		err := CheckSimple(cfg)
		assert.NoError(t, err)
	})

	t.Run("only dynamic does not trigger exclusion", func(t *testing.T) {
		cfg := model.OIDCRPConfig{
			Enable: true,
			Registration: &model.OIDCRPRegistrationConfig{
				Dynamic: &model.OIDCRPDynamicRegistrationConfig{},
			},
			RedirectURI:        "https://example.com/callback",
			IssuerURL:          "https://issuer.example.com",
			Scopes:             []string{"openid"},
			CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
		}
		require.NoError(t, defaults.Set(&cfg))

		err := CheckSimple(cfg)
		assert.NoError(t, err)
	})

	t.Run("neither set triggers registration required", func(t *testing.T) {
		cfg := model.OIDCRPConfig{
			Enable:            true,
			RedirectURI:        "https://example.com/callback",
			IssuerURL:          "https://issuer.example.com",
			Scopes:             []string{"openid"},
			CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
		}
		require.NoError(t, defaults.Set(&cfg))

		err := CheckSimple(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required_if")
		assert.NotContains(t, err.Error(), "excluded_with")
	})
}
