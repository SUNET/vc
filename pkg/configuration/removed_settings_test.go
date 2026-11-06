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

// Each removed seed-commitment setting stops the loader, which names it.
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
			name:   "config commitments",
			config: "common:\n  credential_metadata:\n    pid:\n      commitments:\n        ssc:\n          seed: primary\n",
			path:   "common.credential_metadata.pid.commitments",
		},
		{
			name:    "secrets apigw.seeds",
			config:  "common:\n  secret_file_path: %SECRETS%\n",
			secrets: "apigw:\n  seeds:\n    primary:\n      secret: c2VjcmV0\n",
			path:    "apigw.seeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			secretsPath := filepath.Join(dir, "secrets.yaml")
			require.NoError(t, os.WriteFile(secretsPath, []byte(tt.secrets), 0o600))
			configPath := filepath.Join(dir, "config.yaml")
			config := []byte(strings.ReplaceAll(tt.config, "%SECRETS%", secretsPath))
			require.NoError(t, os.WriteFile(configPath, config, 0o600))
			t.Setenv("VC_CONFIG_YAML", configPath)

			_, err := New(context.Background(), "apigw")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.path+" is removed")
		})
	}
}
