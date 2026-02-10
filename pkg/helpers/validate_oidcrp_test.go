package helpers

import (
	"testing"
	"vc/pkg/model"

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
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "valid config with static credentials",
			config: model.OIDCRPConfig{
				Enabled:            true,
				ClientID:           "test-client",
				ClientSecret:       "test-secret",
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
				Enabled:     true,
				RedirectURI: "https://example.com/callback",
				IssuerURL:   "https://issuer.example.com",
				Scopes:      []string{"openid"},
				DynamicRegistration: model.DynamicRegistrationConfig{
					Enabled: true,
				},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "valid config with default scopes",
			config: model.OIDCRPConfig{
				Enabled:            true,
				ClientID:           "test-client",
				ClientSecret:       "test-secret",
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
				Enabled:            true,
				ClientID:           "test-client",
				ClientSecret:       "test-secret",
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"profile", "email"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "oidc_openid_scope_required",
		},
		{
			name: "missing credentials without dynamic registration",
			config: model.OIDCRPConfig{
				Enabled:            true,
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "oidc_credentials_required",
		},
		{
			name: "missing client_id only",
			config: model.OIDCRPConfig{
				Enabled:            true,
				ClientSecret:       "test-secret",
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "oidc_credentials_required",
		},
		{
			name: "missing client_secret only",
			config: model.OIDCRPConfig{
				Enabled:            true,
				ClientID:           "test-client",
				RedirectURI:        "https://example.com/callback",
				IssuerURL:          "https://issuer.example.com",
				Scopes:             []string{"openid"},
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: true,
			errorMsg:    "oidc_credentials_required",
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
