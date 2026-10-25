package primitives

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known answers from a separate RFC 5869 HKDF-SHA256 in Python, over the
// construction in docs/issuer/AUXILIARY_DATA.md, and one fixture per
// refusal.
func TestHKDFOpening(t *testing.T) {
	writeSecret := func(n int) string {
		path := filepath.Join(t.TempDir(), "secret.key")
		require.NoError(t, os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("s"), n))), 0o600))
		return path
	}
	secretPath := writeSecret(32)
	opening := func(n, inputs int) *HKDFOpeningArgs {
		return &HKDFOpeningArgs{SecretPath: secretPath, Inputs: make([]string, inputs), Bytes: n}
	}

	for _, tc := range []struct {
		bytes  int
		values []string
		want   string
	}{
		{16, []string{"SE", "pan-200"}, "2a9e95e7a753cf6199b1f14f1390adf5"},
		{32, []string{"SE", "pan-200"}, "6ddd42078eb9ee84792b833540bbf2a570cda993ab81cac34bba1e88d6c755e9"},
		{16, []string{"198001011234"}, "6166c54332416b2fc137ae625749565a"},
	} {
		got, err := opening(tc.bytes, len(tc.values)).OpenValues(tc.values)
		require.NoError(t, err, tc.values)
		assert.Equal(t, tc.want, hex.EncodeToString(got), "%d bytes of %q", tc.bytes, tc.values)
	}

	short := opening(16, 1)
	short.SecretPath = writeSecret(31)
	_, err := short.OpenValues([]string{"SE"})
	assert.ErrorContains(t, err, "shorter than 32 bytes")
	_, err = opening(16, 2).OpenValues([]string{"SE", " "})
	assert.ErrorIs(t, err, ErrInvalidClaimInput)
	_, err = opening(16, 1).OpenValues([]string{strings.Repeat("a", maxHKDFField+1)})
	assert.ErrorContains(t, err, "longer than 65535 bytes")
}
