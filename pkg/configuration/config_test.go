package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

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
      basic_auth:
        users:
          admin: "secret-admin-pass"
  oidcrp:
    registration:
      preconfigured:
        client_secret: "secret-client-secret"
      dynamic:
        initial_access_token: "secret-initial-token"
registry:
  admin_gui:
    password: "secret-registry-pass"
verifier:
  oidc:
    subject_salt: "secret-salt-value"
ui:
  password: "secret-ui-pass"
`, testMongoURI)
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(content), 0600))

	secrets, err := LoadSecrets(secretsPath)
	require.NoError(t, err)

	// Verify common secrets
	require.NotNil(t, secrets.Common)
	assert.Equal(t, testMongoURI, secrets.Common.Mongo.URI)

	// Verify APIGW secrets
	require.NotNil(t, secrets.APIGW)
	assert.Equal(t, "secret-admin-pass", secrets.APIGW.APIServer.APIAuth.BasicAuth.Users["admin"])
	require.NotNil(t, secrets.APIGW.OIDCRP.Registration.Preconfigured)
	assert.Equal(t, "secret-client-secret", secrets.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret)
	require.NotNil(t, secrets.APIGW.OIDCRP.Registration.Dynamic)
	assert.Equal(t, "secret-initial-token", secrets.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken)

	// Verify Registry secrets
	require.NotNil(t, secrets.Registry)
	assert.Equal(t, "secret-registry-pass", secrets.Registry.AdminGUI.Password)

	// Verify Verifier secrets
	require.NotNil(t, secrets.Verifier)
	assert.Equal(t, "secret-salt-value", secrets.Verifier.OIDC.SubjectSalt)

	// Verify UI secrets
	require.NotNil(t, secrets.UI)
	assert.Equal(t, "secret-ui-pass", secrets.UI.Password)
}

func TestLoadSecrets_FileNotFound(t *testing.T) {
	_, err := LoadSecrets("/nonexistent/path/secrets.yaml")
	assert.Error(t, err)
}

func TestLoadSecrets_DirectoryPath(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := LoadSecrets(tmpDir)
	assert.Error(t, err)
}

func TestLoadSecrets_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte("{{not valid yaml"), 0600))

	_, err := LoadSecrets(secretsPath)
	assert.Error(t, err)
}

func TestLoadSecrets_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "empty.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(""), 0600))

	secrets, err := LoadSecrets(secretsPath)
	require.NoError(t, err)

	assert.Nil(t, secrets.Common)
	assert.Nil(t, secrets.APIGW)
}

func TestLoadSecrets_PartialSecrets(t *testing.T) {
	content := `---
ui:
  password: "only-ui-password"
`
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "partial.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(content), 0600))

	secrets, err := LoadSecrets(secretsPath)
	require.NoError(t, err)

	require.NotNil(t, secrets.UI)
	assert.Equal(t, "only-ui-password", secrets.UI.Password)
	assert.Nil(t, secrets.Common)
}
