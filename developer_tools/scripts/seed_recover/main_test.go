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

	// The inline field is gone from the main configuration, so recovery
	// must refuse rather than quietly reproduce a seed from a value the
	// ISSUER would not have used. A tool that accepted it here would
	// hand back seeds the issuer never derived.
	t.Run("an inline secret in the main config is not a source", func(t *testing.T) {
		dir := t.TempDir()
		configPath := write(t, dir, "config.yaml",
			"issuer:\n  seeds:\n    pseudonym:\n      model: derived\n      secret: \""+secret+"\"\n", 0o600)

		_, err := loadSeedSource(configPath, "pseudonym")
		require.Error(t, err, "config.yaml is no longer a place the derivation secret can live")
		assert.Contains(t, err.Error(), "secret_path")
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

// A malformed -expect is an input error, not a mismatch.
//
// A valid-hex value of the wrong length decoded happily and then compared
// unequal to everything, so the documented remapping loop reported
// "match: no" for every candidate - telling the operator that no subject
// matches, when the truth is that the value they passed is not a
// pseudonym at all.
func TestExpectMustBeAFullLengthDigest(t *testing.T) {
	const valid = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	for _, tc := range []struct{ name, in string }{
		{"too short", "00"},
		{"one byte short", valid[:len(valid)-2]},
		{"too long", valid + "ab"},
		{"whitespace only", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExpectation(tc.in)
			require.Error(t, err, "this cannot match any subject, so it must not be reported as a mismatch")
			assert.Contains(t, err.Error(), "-expect")
		})
	}

	t.Run("not hex at all", func(t *testing.T) {
		_, err := parseExpectation("zz")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not hex")
	})

	t.Run("a real digest, with surrounding whitespace", func(t *testing.T) {
		got, err := parseExpectation("  " + valid + "\n")
		require.NoError(t, err, "an operator pasting a value must not be punished for a newline")
		assert.Len(t, got, 32)
	})
}
