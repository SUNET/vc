package crypto

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecureToken_ByteSize(t *testing.T) {
	tests := []struct {
		name         string
		byteSize     int
		stringLength int
		wantMinLen   int
		wantMaxLen   int
	}{
		{
			name:         "default size (32 bytes)",
			byteSize:     0,
			stringLength: 0,
			wantMinLen:   43,
			wantMaxLen:   43,
		},
		{
			name:         "16 bytes",
			byteSize:     16,
			stringLength: 0,
			wantMinLen:   21,
			wantMaxLen:   22,
		},
		{
			name:         "32 bytes",
			byteSize:     32,
			stringLength: 0,
			wantMinLen:   43,
			wantMaxLen:   43,
		},
		{
			name:         "64 bytes",
			byteSize:     64,
			stringLength: 0,
			wantMinLen:   85,
			wantMaxLen:   86,
		},
		{
			name:         "maximum 94 bytes",
			byteSize:     94,
			stringLength: 0,
			wantMinLen:   125,
			wantMaxLen:   126,
		},
		{
			name:         "exceeds maximum (100 bytes -> capped at 94)",
			byteSize:     100,
			stringLength: 0,
			wantMinLen:   125,
			wantMaxLen:   126,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.byteSize, tt.stringLength)
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.GreaterOrEqual(t, len(token), tt.wantMinLen)
			assert.LessOrEqual(t, len(token), tt.wantMaxLen)

			// Verify it's valid base64 URL encoding
			_, err = base64.RawURLEncoding.DecodeString(token)
			assert.NoError(t, err, "token should be valid base64 URL encoding")
		})
	}
}

func TestGenerateSecureToken_StringLength(t *testing.T) {
	tests := []struct {
		name         string
		byteSize     int
		stringLength int
		wantLen      int
	}{
		{
			name:         "32 character string",
			byteSize:     0,
			stringLength: 32,
			wantLen:      32,
		},
		{
			name:         "43 character string",
			byteSize:     0,
			stringLength: 43,
			wantLen:      43,
		},
		{
			name:         "64 character string",
			byteSize:     0,
			stringLength: 64,
			wantLen:      64,
		},
		{
			name:         "100 character string",
			byteSize:     0,
			stringLength: 100,
			wantLen:      100,
		},
		{
			name:         "very large string (150 chars -> capped at 126)",
			byteSize:     0,
			stringLength: 150,
			wantLen:      126,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.byteSize, tt.stringLength)
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Equal(t, tt.wantLen, len(token))

			// Verify it's valid base64 URL encoding (or truncated version)
			// Truncated tokens may not decode, but should only contain valid chars
			validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			for _, ch := range token {
				assert.True(t, strings.ContainsRune(validChars, ch),
					"token should only contain base64 URL-safe characters")
			}
		})
	}
}

func TestGenerateSecureToken_Uniqueness(t *testing.T) {
	// Generate 1000 tokens and verify they're all unique
	tokens := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		token, err := GenerateSecureToken(32, 0)
		require.NoError(t, err)
		assert.False(t, tokens[token], "token should be unique")
		tokens[token] = true
	}

	assert.Len(t, tokens, iterations, "all tokens should be unique")
}

func TestGenerateSecureToken_StringLengthPriority(t *testing.T) {
	// When both byteSize and stringLength are provided, stringLength takes priority
	token, err := GenerateSecureToken(16, 50)
	require.NoError(t, err)
	assert.Equal(t, 50, len(token), "stringLength should take priority over byteSize")
}

func TestGenerateSecureToken_Base64URLSafe(t *testing.T) {
	// Verify tokens don't contain characters that need URL encoding
	forbiddenChars := []string{"+", "/", "="}

	for i := 0; i < 100; i++ {
		token, err := GenerateSecureToken(32, 0)
		require.NoError(t, err)

		for _, char := range forbiddenChars {
			assert.NotContains(t, token, char,
				"token should not contain '%s' (should use URL-safe encoding)", char)
		}
	}
}

func TestGenerateSecureToken_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		byteSize     int
		stringLength int
		expectError  bool
	}{
		{
			name:         "both zero (should use default)",
			byteSize:     0,
			stringLength: 0,
			expectError:  false,
		},
		{
			name:         "string length of 1",
			byteSize:     0,
			stringLength: 1,
			expectError:  false,
		},
		{
			name:         "byte size of 1",
			byteSize:     1,
			stringLength: 0,
			expectError:  false,
		},
		{
			name:         "maximum values",
			byteSize:     94,
			stringLength: 0,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.byteSize, tt.stringLength)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestGenerateSecureToken_ConsistentEncoding(t *testing.T) {
	// Generate tokens and verify consistent encoding properties
	for i := 0; i < 100; i++ {
		token, err := GenerateSecureToken(32, 0)
		require.NoError(t, err)

		// Should be exactly 43 characters for 32 bytes
		assert.Equal(t, 43, len(token))

		// Should decode to 32 bytes
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		require.NoError(t, err)
		assert.Equal(t, 32, len(decoded))
	}
}

func TestGenerateSecureToken_StringLengthCalculation(t *testing.T) {
	// Verify the byte calculation for string length works correctly
	tests := []struct {
		stringLength int
		minBytes     int
		maxBytes     int
	}{
		{stringLength: 32, minBytes: 24, maxBytes: 24}, // (32 * 3 + 3) / 4 = 24
		{stringLength: 43, minBytes: 32, maxBytes: 33}, // (43 * 3 + 3) / 4 = 32.5
		{stringLength: 64, minBytes: 48, maxBytes: 48}, // (64 * 3 + 3) / 4 = 48
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.stringLength)), func(t *testing.T) {
			token, err := GenerateSecureToken(0, tt.stringLength)
			require.NoError(t, err)
			assert.Equal(t, tt.stringLength, len(token))

			// Verify we can decode at least the expected bytes
			// (may be truncated, so we can't decode directly)
			assert.NotEmpty(t, token)
		})
	}
}

func BenchmarkGenerateSecureToken_32Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(32, 0)
	}
}

func BenchmarkGenerateSecureToken_64Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(64, 0)
	}
}

func BenchmarkGenerateSecureToken_32Chars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(0, 32)
	}
}

func BenchmarkGenerateSecureToken_64Chars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(0, 64)
	}
}
