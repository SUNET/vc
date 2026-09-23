package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSecrets_ValidFile(t *testing.T) {
	testMongoURI := "mongodb://secret-user:secret-pass@host:27017" //NOSONAR
	content := fmt.Sprintf(`---
common:
  mongo:
    uri: "%s"
apigw:
  api_server:
    api_auth:
      oidc:
        client_secret: "secret-oidc-client"
  auth_providers:
    oidc:
        registration:
          preconfigured:
            client_secret: "secret-client-secret"
          dynamic:
            initial_access_token: "secret-initial-token"
registry:
  admin_gui:
    password: "secret-registry-pass"
verifier:
  outbound:
    oidc_provider:
      subject_salt: "secret-salt-value"
`, testMongoURI)
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(content), 0o600))

	secrets, err := LoadSecrets(secretsPath, false)
	require.NoError(t, err)

	// Verify common secrets
	require.NotNil(t, secrets.Common)
	assert.Equal(t, testMongoURI, secrets.Common.Mongo.URI)

	// Verify APIGW secrets
	require.NotNil(t, secrets.APIGW)
	assert.Equal(t, "secret-oidc-client", secrets.APIGW.APIServer.APIAuth.OIDC.ClientSecret)
	require.NotNil(t, secrets.APIGW.AuthProviders.OIDC.Registration.Preconfigured)
	assert.Equal(t, "secret-client-secret", secrets.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret)
	require.NotNil(t, secrets.APIGW.AuthProviders.OIDC.Registration.Dynamic)
	assert.Equal(t, "secret-initial-token", secrets.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken)

	// Verify Registry secrets
	require.NotNil(t, secrets.Registry)
	assert.Equal(t, "secret-registry-pass", secrets.Registry.AdminGUI.Password)

	// Verify Verifier secrets
	require.NotNil(t, secrets.Verifier)
	assert.Equal(t, "secret-salt-value", secrets.Verifier.Outbound.OIDCProvider.SubjectSalt)
}

func TestLoadSecrets_FileNotFound(t *testing.T) {
	_, err := LoadSecrets("/nonexistent/path/secrets.yaml", false)
	assert.Error(t, err)
}

func TestLoadSecrets_DirectoryPath(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := LoadSecrets(tmpDir, false)
	assert.Error(t, err)
}

func TestLoadSecrets_OverlyPermissiveMode(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte("---\n"), 0o644))

	_, err := LoadSecrets(secretsPath, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overly permissive mode")
}

func TestLoadSecrets_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte("{{not valid yaml"), 0o600))

	_, err := LoadSecrets(secretsPath, false)
	assert.Error(t, err)
}

func TestLoadSecrets_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "empty.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(""), 0o600))

	secrets, err := LoadSecrets(secretsPath, false)
	require.NoError(t, err)

	assert.Nil(t, secrets.Common)
	assert.Nil(t, secrets.APIGW)
}

func TestLoadSecrets_PartialSecrets(t *testing.T) {
	content := `---
registry:
  admin_gui:
    password: "only-registry-password"
`
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "partial.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(content), 0o600))

	secrets, err := LoadSecrets(secretsPath, false)
	require.NoError(t, err)

	require.NotNil(t, secrets.Registry)
	assert.Equal(t, "only-registry-password", secrets.Registry.AdminGUI.Password)
	assert.Nil(t, secrets.Common)
}

func TestDigitalCredentialsDefaults(t *testing.T) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{},
	}
	require.NoError(t, defaults.Set(cfg))

	dc := cfg.Verifier.DigitalCredentials

	assert.Equal(t, []string{"vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"}, dc.PreferredFormats,
		"PreferredFormats should have default values from struct tag")
	assert.Equal(t, "dc_api.jwt", dc.ResponseMode,
		"ResponseMode should default to dc_api.jwt")
	assert.False(t, dc.Enable,
		"Enable should default to false")
	assert.False(t, dc.UseJAR,
		"UseJAR should default to false")
}

func TestSignMetadataRateLimitDefaults(t *testing.T) {
	cfg := &model.Cfg{
		Issuer: &model.Issuer{},
	}
	require.NoError(t, defaults.Set(cfg))

	rl := cfg.Issuer.SignMetadataRateLimit

	assert.Equal(t, 2.0, rl.RequestsPerSecond,
		"RequestsPerSecond should default to 2")
	assert.Equal(t, 20, rl.Burst,
		"Burst should default to 20")
}

// Every credential offer publishes credential_offers.issuer_url as
// `credential_issuer`, but issuer metadata is generated from apigw.public_url
// and declares THAT. When the two disagree a wallet resolves the offer to an
// origin serving no metadata (or metadata naming someone else) and discovery
// fails - silently, at the end of a flow, inside the wallet. There is no
// deployment on the far side of that, so config load refuses it.
func TestCheckCredentialOfferIssuerIdentity(t *testing.T) {
	newCfg := func(issuerURL, publicURL string) *model.Cfg {
		return &model.Cfg{APIGW: &model.APIGW{
			PublicURL: publicURL,
			Delivery: model.APIGWDelivery{
				CredentialOffers: model.CredentialOffers{IssuerURL: issuerURL},
			},
		}}
	}

	tests := []struct {
		name        string
		issuerURL   string
		publicURL   string
		service     string
		wantErr     bool
		errContains string
	}{
		{name: "equal", issuerURL: "https://a.example", publicURL: "https://a.example", service: "apigw"},
		{name: "equal but for a trailing slash", issuerURL: "https://a.example/", publicURL: "https://a.example", service: "apigw"},
		{
			name: "different origins", issuerURL: "https://issuer.example", publicURL: "https://apigw.example",
			service: "apigw", wantErr: true, errContains: "must equal apigw.public_url",
		},
		{
			name: "different scheme only", issuerURL: "http://a.example", publicURL: "https://a.example",
			service: "apigw", wantErr: true, errContains: "must equal apigw.public_url",
		},
		// Absence is the required-tag's business, not this check's.
		{name: "issuer url unset", issuerURL: "", publicURL: "https://a.example", service: "apigw"},
		{name: "public url unset", issuerURL: "https://a.example", publicURL: "", service: "apigw"},
		// Only apigw builds credential offers.
		{name: "not apigw", issuerURL: "https://issuer.example", publicURL: "https://apigw.example", service: "verifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCredentialOfferIssuerIdentity(newCfg(tt.issuerURL, tt.publicURL), tt.service)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}
