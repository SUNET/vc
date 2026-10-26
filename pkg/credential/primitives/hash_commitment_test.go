package primitives

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known answers from a separate RFC 5869 HKDF-SHA256 and RFC 2104
// HMAC-SHA256 in Python, over the construction in
// docs/issuer/AUXILIARY_DATA.md, and one fixture per refusal of each keyed
// generator.
func TestKeyedOpening(t *testing.T) {
	writeSecret := func(n int) string {
		path := filepath.Join(t.TempDir(), "secret.key")
		require.NoError(t, os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("s"), n))), 0o600))
		return path
	}
	secretPath, shortSecretPath := writeSecret(32), writeSecret(31)
	generators := []struct {
		name     string
		maxBytes int
		opening  func(secretPath string, n, inputs int) KeyedOpening
	}{
		{"hkdf", 64, func(secretPath string, n, inputs int) KeyedOpening {
			return &HKDFOpeningArgs{SecretPath: secretPath, Inputs: make([]string, inputs), Bytes: n}
		}},
		{"hmac", 32, func(secretPath string, n, inputs int) KeyedOpening {
			return &HMACOpeningArgs{SecretPath: secretPath, Inputs: make([]string, inputs), Bytes: n}
		}},
	}
	hkdf, hmac := generators[0], generators[1]

	for _, tc := range []struct {
		opening KeyedOpening
		values  []string
		want    string
	}{
		{hkdf.opening(secretPath, 16, 2), []string{"SE", "pan-200"}, "2a9e95e7a753cf6199b1f14f1390adf5"},
		{hkdf.opening(secretPath, 32, 2), []string{"SE", "pan-200"}, "6ddd42078eb9ee84792b833540bbf2a570cda993ab81cac34bba1e88d6c755e9"},
		{hkdf.opening(secretPath, 16, 1), []string{"198001011234"}, "6166c54332416b2fc137ae625749565a"},
		// Python's hmac and `openssl dgst -sha256 -mac HMAC -macopt
		// hexkey:<"s" x 32>` over the message
		// 001a76632f686173685f636f6d6d69746d656e742f686d61632f76310002313600025345000770616e2d323030,
		// truncated to 16 bytes.
		{hmac.opening(secretPath, 16, 2), []string{"SE", "pan-200"}, "f59cf3a69d931f579a134c0bfdd5a75b"},
	} {
		got, err := tc.opening.OpenValues(tc.values)
		require.NoError(t, err, tc.values)
		assert.Equal(t, tc.want, hex.EncodeToString(got), "%#v of %q", tc.opening, tc.values)
	}

	for _, g := range generators {
		for rule, tc := range map[string]struct {
			opening KeyedOpening
			values  []string
			want    string
		}{
			"the secret has 32 bytes":         {g.opening(shortSecretPath, 16, 1), []string{"SE"}, "shorter than 32 bytes"},
			"an input is not blank":           {g.opening(secretPath, 16, 2), []string{"SE", " "}, "must be a non-empty string"},
			"an input fits its length prefix": {g.opening(secretPath, 16, 1), []string{strings.Repeat("a", maxField+1)}, "longer than 65535 bytes"},
			"the opening fits the generator":  {g.opening(secretPath, g.maxBytes+1, 1), []string{"SE"}, fmt.Sprintf("16 to %d bytes, got %d", g.maxBytes, g.maxBytes+1)},
		} {
			_, err := tc.opening.OpenValues(tc.values)
			assert.ErrorContains(t, err, tc.want, "%s: %s", g.name, rule)
		}
	}
}

// One fixture per refusal of a claim opening. Each error names the claim
// and never its value, which is a secret.
func TestClaimOpeningRefusals(t *testing.T) {
	opening := &ClaimOpeningArgs{Input: "subject.opening"}
	for rule, tc := range map[string]struct {
		value any
		want  string
	}{
		"the claim is present":           {nil, "must be a string"},
		"the claim is a string":          {[]any{"AAECAwQFBgcICQoLDA0ODw"}, "must be a string"},
		"the claim is base64url":         {"AAECAwQFBgcICQoLDA0ODw+/", "not valid base64url"},
		"the claim has 16 bytes":         {"1990-01-01", "16 to 64 bytes, got 7"},
		"the claim has at most 64 bytes": {base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)), "16 to 64 bytes, got 65"},
	} {
		claims := map[string]any{"subject": map[string]any{}}
		if tc.value != nil {
			claims["subject"] = map[string]any{"opening": tc.value}
		}
		_, err := opening.open(claims)
		require.ErrorIs(t, err, ErrInvalidClaimInput, rule)
		assert.ErrorContains(t, err, `"subject.opening"`, rule)
		assert.ErrorContains(t, err, tc.want, rule)
		if s, ok := tc.value.(string); ok {
			assert.NotContains(t, err.Error(), s, rule)
		}
	}
}
