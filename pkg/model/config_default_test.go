package model

import (
	"testing"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIServerDefaults(t *testing.T) {
	var cfg APIServer
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.Addr)
	assert.False(t, cfg.TLS.Enabled)
}

func TestTLSDefaults(t *testing.T) {
	var cfg TLS
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
}

func TestCORSDefaults(t *testing.T) {
	var cfg CORS
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.NotNil(t, cfg.AllowedOrigins)
	assert.Len(t, cfg.AllowedOrigins, 0)
}

func TestKafkaDefaults(t *testing.T) {
	var cfg Kafka
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, []string{"kafka0:9092", "kafka1:9092"}, cfg.Brokers)
}

func TestCredentialOfferQRConfigDefaults(t *testing.T) {
	var cfg CredentialOfferQRConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "credential_offer", cfg.Type)
}

func TestQRCfgDefaults(t *testing.T) {
	var cfg QRCfg
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, 2, cfg.RecoveryLevel)
	assert.Equal(t, 256, cfg.Size)
}

func TestGRPCServerDefaults(t *testing.T) {
	var cfg GRPCServer
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, ":8090", cfg.Addr)
}

func TestGRPCTLSDefaults(t *testing.T) {
	var cfg GRPCTLS
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "/pki/grpc_server.crt", cfg.CertFilePath)
	assert.Equal(t, "/pki/grpc_server.key", cfg.KeyFilePath)
	assert.Equal(t, "/pki/client_ca.crt", cfg.ClientCAPath)
}

func TestJWTAttributeDefaults(t *testing.T) {
	var cfg JWTAttribute
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.EnableNotBefore)
	assert.Equal(t, int64(3600), cfg.ValidDuration)
}

func TestSAMLConfigDefaults(t *testing.T) {
	var cfg SAMLConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
}

func TestOIDCRPConfigDefaults(t *testing.T) {
	var cfg OIDCRPConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
	assert.Equal(t, []string{"openid", "profile", "email"}, cfg.Scopes)
}

func TestDynamicRegistrationConfigDefaults(t *testing.T) {
	var cfg DynamicRegistrationConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
}

func TestAttributeConfigDefaults(t *testing.T) {
	var cfg AttributeConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Required)
}

func TestAuditLogDefaults(t *testing.T) {
	var cfg AuditLog
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
}

func TestMDocConfigDefaults(t *testing.T) {
	var cfg MDocConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Contains(t, cfg.DefaultValidity.String(), "8760h")
	assert.Equal(t, "SHA-256", cfg.DigestAlgorithm)
}

func TestGRPCClientTLSDefaults(t *testing.T) {
	var cfg GRPCClientTLS
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.TLS)
}

func TestPKCS11Defaults(t *testing.T) {
	var cfg PKCS11
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "/usr/lib/softhsm/libsofthsm2.so", cfg.ModulePath)
	assert.Equal(t, uint(0), cfg.SlotID)
	assert.Empty(t, cfg.PIN)
	assert.Empty(t, cfg.KeyLabel)
	assert.Empty(t, cfg.KeyID)
}

func TestAdminGUIDefaults(t *testing.T) {
	var cfg AdminGUI
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "admin", cfg.Username)
}

func TestMockASDefaults(t *testing.T) {
	var cfg MockAS
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, []string{"100", "102"}, cfg.BootstrapUsers)
}

func TestTrustConfigDefaults(t *testing.T) {
	var cfg TrustConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.True(t, cfg.Enabled)
	assert.Equal(t, []string{"did:key", "did:jwk"}, cfg.LocalDIDMethods)
}

func TestTrustPolicyConfigDefaults(t *testing.T) {
	var cfg TrustPolicyConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.RequireRevocationCheck)
}

func TestOIDCConfigDefaults(t *testing.T) {
	var cfg OIDCConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, 3600, cfg.SessionDuration)
	assert.Equal(t, 300, cfg.CodeDuration)
	assert.Equal(t, 3600, cfg.AccessTokenDuration)
	assert.Equal(t, 3600, cfg.IDTokenDuration)
	assert.Equal(t, 86400, cfg.RefreshTokenDuration)
}

func TestOpenID4VPConfigDefaults(t *testing.T) {
	var cfg OpenID4VPConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, 300, cfg.PresentationTimeout)
}

func TestDigitalCredentialsConfigDefaults(t *testing.T) {
	var cfg DigitalCredentialsConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
	assert.False(t, cfg.UseJAR)
	assert.Equal(t, []string{"vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"}, cfg.PreferredFormats)
	assert.Equal(t, "dc_api.jwt", cfg.ResponseMode)
	assert.True(t, cfg.AllowQRFallback)
}

func TestAuthorizationPageCSSConfigDefaults(t *testing.T) {
	var cfg AuthorizationPageCSSConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, "light", cfg.Theme)
}

func TestCredentialDisplayConfigDefaults(t *testing.T) {
	var cfg CredentialDisplayConfig
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
	assert.False(t, cfg.RequireConfirmation)
	assert.False(t, cfg.ShowRawCredential)
	assert.True(t, cfg.ShowClaims)
	assert.False(t, cfg.AllowEdit)
}

func TestBasicAuthDefaults(t *testing.T) {
	var cfg BasicAuth
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.False(t, cfg.Enabled)
}

func TestTokenStatusListsDefaults(t *testing.T) {
	var cfg TokenStatusLists
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, int64(43200), cfg.TokenRefreshInterval)
	assert.Equal(t, int64(1000000), cfg.SectionSize)
	assert.Equal(t, 60, cfg.RateLimitRequestsPerMinute)
}

func TestOTELDefaults(t *testing.T) {
	var cfg OTEL
	err := defaults.Set(&cfg)
	require.NoError(t, err)

	assert.Equal(t, int64(10), cfg.Timeout)
}

func TestOIDCRPConfigScopesValidation(t *testing.T) {
	tests := []struct {
		name        string
		scopes      []string
		enabled     bool
		wantErr     bool
		errContains string
	}{
		{
			name:    "default scopes with openid",
			scopes:  []string{"openid", "profile", "email"},
			enabled: true,
			wantErr: false,
		},
		{
			name:        "missing openid scope",
			scopes:      []string{"profile", "email"},
			enabled:     true,
			wantErr:     true,
			errContains: "must include 'openid'",
		},
		{
			name:    "only openid scope",
			scopes:  []string{"openid"},
			enabled: true,
			wantErr: false,
		},
		{
			name:    "disabled config no validation",
			scopes:  []string{"profile"},
			enabled: false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &OIDCRPConfig{
				Enabled: tt.enabled,
				Scopes:  tt.scopes,
			}

			// Set client credentials for validation
			if tt.enabled {
				cfg.ClientID = "test-client"
				cfg.ClientSecret = "test-secret"
				cfg.RedirectURI = "https://example.com/callback"
				cfg.IssuerURL = "https://provider.example.com"
			}

			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSAMLConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *SAMLConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "disabled config",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{Enabled: false}
			},
			wantErr: false,
		},
		{
			name: "valid MDQ config",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled:         true,
					MDQServer:       "https://md.example.org/entities/",
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr: false,
		},
		{
			name: "valid static IdP config with path",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled: true,
					StaticIDPMetadata: &StaticIDPConfig{
						EntityID:     "https://idp.example.com",
						MetadataPath: "/metadata/idp.xml",
					},
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr: false,
		},
		{
			name: "valid static IdP config with URL",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled: true,
					StaticIDPMetadata: &StaticIDPConfig{
						EntityID:    "https://idp.example.com",
						MetadataURL: "https://idp.example.com/metadata",
					},
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr: false,
		},
		{
			name: "neither MDQ nor static IdP",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled:         true,
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr:     true,
			errContains: "neither mdq_server nor static_idp_metadata",
		},
		{
			name: "both MDQ and static IdP",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled:   true,
					MDQServer: "https://md.example.org/entities/",
					StaticIDPMetadata: &StaticIDPConfig{
						EntityID:     "https://idp.example.com",
						MetadataPath: "/metadata/idp.xml",
					},
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr:     true,
			errContains: "cannot have both mdq_server and static_idp_metadata",
		},
		{
			name: "static IdP with both path and URL",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled: true,
					StaticIDPMetadata: &StaticIDPConfig{
						EntityID:     "https://idp.example.com",
						MetadataPath: "/metadata/idp.xml",
						MetadataURL:  "https://idp.example.com/metadata",
					},
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr:     true,
			errContains: "cannot have both metadata_path and metadata_url",
		},
		{
			name: "static IdP without metadata",
			setupConfig: func() *SAMLConfig {
				return &SAMLConfig{
					Enabled: true,
					StaticIDPMetadata: &StaticIDPConfig{
						EntityID: "https://idp.example.com",
					},
					EntityID:        "https://sp.example.com",
					CertificatePath: "/pki/saml.crt",
					PrivateKeyPath:  "/pki/saml.key",
					ACSEndpoint:     "https://sp.example.com/acs",
				}
			},
			wantErr:     true,
			errContains: "requires either metadata_path or metadata_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupConfig()
			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
