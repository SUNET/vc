package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Success(t *testing.T) {
	yaml := `
wallet:
  key_path: /keys/wallet.pem
  key_algorithm: RS256
  client_id: my-wallet
api_server:
  addr: ":9090"
scenarios:
  - name: issuance
    type: vci
    auto_run: true
    vci:
      issuer_url: https://issuer.example.com
      scope: openid
`
	path := writeTemp(t, yaml)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "/keys/wallet.pem", cfg.Wallet.KeyPath)
	assert.Equal(t, "RS256", cfg.Wallet.KeyAlgorithm)
	assert.Equal(t, "my-wallet", cfg.Wallet.ClientID)
	assert.Equal(t, ":9090", cfg.APIServer.Addr)
	require.Len(t, cfg.Scenarios, 1)
	assert.Equal(t, "issuance", cfg.Scenarios[0].Name)
	assert.Equal(t, "vci", cfg.Scenarios[0].Type)
	assert.True(t, cfg.Scenarios[0].AutoRun)
	require.NotNil(t, cfg.Scenarios[0].VCI)
	assert.Equal(t, "https://issuer.example.com", cfg.Scenarios[0].VCI.IssuerURL)
	assert.Equal(t, "openid", cfg.Scenarios[0].VCI.Scope)
}

func TestLoad_UnreadableFile(t *testing.T) {
	_, err := Load("/non/existent/path.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading wallet config")
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{not valid yaml}}")

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing wallet config")
}

func TestLoad_DefaultAddr(t *testing.T) {
	path := writeTemp(t, `
wallet:
  key_path: /keys/wallet.pem
  key_algorithm: RS256
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.APIServer.Addr, "api_server.addr should default to :8080")
}

func TestLoad_DefaultKeyAlgorithm(t *testing.T) {
	path := writeTemp(t, `
wallet:
  key_path: /keys/wallet.pem
api_server:
  addr: ":9090"
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "ES256", cfg.Wallet.KeyAlgorithm, "wallet.key_algorithm should default to ES256")
}

func TestLoad_BothDefaultsApplied(t *testing.T) {
	path := writeTemp(t, `
wallet:
  key_path: /keys/wallet.pem
`)

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.APIServer.Addr)
	assert.Equal(t, "ES256", cfg.Wallet.KeyAlgorithm)
}

// writeTemp creates a temporary YAML file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}
