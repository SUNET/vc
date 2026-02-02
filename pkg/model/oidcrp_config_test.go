package model

import (
	"testing"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCRPConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  OIDCRPConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "Disabled config is valid",
			config: OIDCRPConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "Valid config with static credentials",
			config: OIDCRPConfig{
				Enabled:      true,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURI:  "https://example.com/callback",
				IssuerURL:    "https://issuer.example.com",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: false,
		},
		{
			name: "Valid config with default scopes",
			config: OIDCRPConfig{
				Enabled:      true,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURI:  "https://example.com/callback",
				IssuerURL:    "https://issuer.example.com",
				// Scopes: nil (zero value) will get defaults applied
			},
			wantErr: false,
		},
		{
			name: "Invalid config - missing openid scope",
			config: OIDCRPConfig{
				Enabled:      true,
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURI:  "https://example.com/callback",
				IssuerURL:    "https://issuer.example.com",
				Scopes:       []string{"profile", "email"}, // Missing 'openid'
			},
			wantErr: true,
			errMsg:  "OIDC scopes must include 'openid'",
		},
		{
			name: "Invalid config - missing credentials without dynamic registration",
			config: OIDCRPConfig{
				Enabled:     true,
				RedirectURI: "https://example.com/callback",
				IssuerURL:   "https://issuer.example.com",
				Scopes:      []string{"openid"},
				// ClientID and ClientSecret missing, DynamicRegistration disabled
			},
			wantErr: true,
			errMsg:  "OIDC RP requires either client_id/client_secret or dynamic_registration.enabled=true",
		},
		{
			name: "Valid config with dynamic registration",
			config: OIDCRPConfig{
				Enabled:     true,
				RedirectURI: "https://example.com/callback",
				IssuerURL:   "https://issuer.example.com",
				Scopes:      []string{"openid"},
				DynamicRegistration: DynamicRegistrationConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid config - missing client_id only",
			config: OIDCRPConfig{
				Enabled:      true,
				ClientSecret: "test-secret",
				RedirectURI:  "https://example.com/callback",
				IssuerURL:    "https://issuer.example.com",
				Scopes:       []string{"openid"},
			},
			wantErr: true,
			errMsg:  "OIDC RP requires either client_id/client_secret or dynamic_registration.enabled=true",
		},
		{
			name: "Invalid config - missing client_secret only",
			config: OIDCRPConfig{
				Enabled:     true,
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				IssuerURL:   "https://issuer.example.com",
				Scopes:      []string{"openid"},
			},
			wantErr: true,
			errMsg:  "OIDC RP requires either client_id/client_secret or dynamic_registration.enabled=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply defaults before validation
			err := defaults.Set(&tt.config)
			require.NoError(t, err)

			err = tt.config.Validate()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				// If scopes were empty, they should now have defaults
				if len(tt.config.Scopes) > 0 {
					// Check that openid is in the scopes
					hasOpenID := false
					for _, scope := range tt.config.Scopes {
						if scope == "openid" {
							hasOpenID = true
							break
						}
					}
					assert.True(t, hasOpenID, "Scopes should include 'openid'")
				}
			}
		})
	}
}
