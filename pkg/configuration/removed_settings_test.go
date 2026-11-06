package configuration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadWithSecrets runs New on config for the issuer, whose configuration has
// no required section. %SECRETS% in config names a file holding secrets.
func loadWithSecrets(t *testing.T, config, secrets string) error {
	t.Helper()
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.yaml")
	require.NoError(t, os.WriteFile(secretsPath, []byte(secrets), 0o600))
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(strings.ReplaceAll(config, "%SECRETS%", secretsPath)), 0o600))
	t.Setenv("VC_CONFIG_YAML", configPath)

	_, err := New(context.Background(), "issuer")
	return err
}

const secretsFileConfig = "common:\n  secret_file_path: %SECRETS%\n"

// Each removed seed-commitment setting stops the loader, which names it.
//
// yaml.v2 decodes a repeated struct key or a root merge into the same pointer,
// so the typed loader combines the fields of both blocks and keeps seeds.
func TestRemovedSeedSettingsAreRefused(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		secrets string
		path    string
	}{
		{
			name:   "config apigw.seeds",
			config: "apigw:\n  seeds:\n    primary:\n      model: derived\n",
			path:   "apigw.seeds",
		},
		{
			name:   "config apigw.seeds then a second apigw block",
			config: "apigw:\n  seeds:\n    primary:\n      model: derived\napigw:\n  external_server_url: x\n",
			path:   "apigw.seeds",
		},
		{
			name:   "config apigw.seeds in a root merge with an explicit apigw block",
			config: "<<:\n  apigw:\n    seeds:\n      primary:\n        model: derived\napigw:\n  external_server_url: x\n",
			path:   "apigw.seeds",
		},
		{
			name:   "config commitments",
			config: "common:\n  credential_metadata:\n    pid:\n      commitments:\n        ssc:\n          seed: primary\n",
			path:   "common.credential_metadata.pid.commitments",
		},
		{
			name:    "secrets apigw.seeds",
			config:  secretsFileConfig,
			secrets: "apigw:\n  seeds:\n    primary:\n      secret: c2VjcmV0\n",
			path:    "apigw.seeds",
		},
		{
			name:    "secrets apigw.seeds then a second apigw block",
			config:  secretsFileConfig,
			secrets: "apigw:\n  seeds:\n    primary:\n      secret: c2VjcmV0\napigw:\n  extra: x\n",
			path:    "apigw.seeds",
		},
		{
			name:    "secrets apigw.seeds in a root merge with an explicit apigw block",
			config:  secretsFileConfig,
			secrets: "<<:\n  apigw:\n    seeds:\n      primary:\n        secret: c2VjcmV0\napigw:\n  extra: x\n",
			path:    "apigw.seeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadWithSecrets(t, tt.config, tt.secrets)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.path+" is removed")
		})
	}
}

// yaml.v2 skips the value of a key its struct has no field for, so an
// unrelated subtree with a key no Go map can hold loads.
func TestUnrelatedSubtreesLoad(t *testing.T) {
	const unrelated = "extra: { ? [a, b] : value }\napigw:\n  extra: { ? [a, b] : value }\n"
	tests := []struct {
		name    string
		config  string
		secrets string
	}{
		{name: "config", config: unrelated},
		{name: "secrets", config: secretsFileConfig, secrets: unrelated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, loadWithSecrets(t, tt.config, tt.secrets))
		})
	}
}
