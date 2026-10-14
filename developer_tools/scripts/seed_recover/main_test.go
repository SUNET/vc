package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The recommended setup puts the derivation secret in the secrets file,
// and this tool is what reproduces a seed from it. A loader that read
// only the main config let ISSUANCE work and made RECOVERY fail - the
// worst place for this to break, since the whole reason the issuer keeps
// a derivation secret is that a seed can be reproduced later.
func TestLoadSeedSourceReadsTheSecretsFile(t *testing.T) {
	const secret = "c2VjcmV0cy1maWxlLXZhbHVlLWF0LWxlYXN0LTMyLWJ5dGVzLWxvbmc"

	write := func(t *testing.T, dir, name, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), mode))
		return path
	}

	t.Run("the secret comes from the secrets file", func(t *testing.T) {
		dir := t.TempDir()
		secretsPath := write(t, dir, "secrets.yaml",
			"issuer:\n  seeds:\n    pseudonym:\n      secret: \""+secret+"\"\n", 0o600)
		configPath := write(t, dir, "config.yaml",
			"common:\n  secret_file_path: \""+secretsPath+"\"\nissuer:\n  seeds:\n    pseudonym:\n      model: derived\n", 0o600)

		source, err := loadSeedSource(configPath, "pseudonym")
		require.NoError(t, err, "the documented setup must be recoverable")
		require.NotNil(t, source)
	})

	t.Run("an inline secret still works, and wins", func(t *testing.T) {
		dir := t.TempDir()
		configPath := write(t, dir, "config.yaml",
			"issuer:\n  seeds:\n    pseudonym:\n      model: derived\n      secret: \""+secret+"\"\n", 0o600)

		source, err := loadSeedSource(configPath, "pseudonym")
		require.NoError(t, err)
		require.NotNil(t, source)
	})

	t.Run("a secrets file this tool may not read is an error, not a fallback", func(t *testing.T) {
		dir := t.TempDir()
		secretsPath := write(t, dir, "secrets.yaml",
			"issuer:\n  seeds:\n    pseudonym:\n      secret: \""+secret+"\"\n", 0o644)
		configPath := write(t, dir, "config.yaml",
			"common:\n  secret_file_path: \""+secretsPath+"\"\nissuer:\n  seeds:\n    pseudonym:\n      model: derived\n", 0o600)

		_, err := loadSeedSource(configPath, "pseudonym")
		require.Error(t, err, "the issuer refuses a world-readable secrets file; recovery must not be laxer")
		assert.Contains(t, err.Error(), "permissive")
	})
}
