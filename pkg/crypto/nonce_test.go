package crypto

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// base64URLCharset matches only base64url characters (RFC 4648 §5) without padding.
var base64URLCharset = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ---------------------------------------------------------------------------
// 1. Default size behaviour (both args zero → 32 random bytes)
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_DefaultSize(t *testing.T) {
	t.Parallel()
	// RawURLEncoding of 32 bytes → ceil(32*4/3) = 43 chars, always.
	const wantChars = 43
	const wantBytes = 32

	for i := 0; i < 50; i++ {
		token, err := GenerateSecureToken(0, 0)
		require.NoError(t, err)
		assert.Len(t, token, wantChars, "default token must be exactly %d chars", wantChars)

		decoded, err := base64.RawURLEncoding.DecodeString(token)
		require.NoError(t, err, "default token must be valid RawURL base64")
		assert.Len(t, decoded, wantBytes, "default token must decode to %d bytes", wantBytes)
	}
}

// ---------------------------------------------------------------------------
// 2. Explicit byteSize values
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_ByteSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		byteSize      int
		wantEncLen    int // base64.RawURLEncoding.EncodedLen(effectiveBytes)
		wantDecBytes  int // effective byte count after clamping
	}{
		{
			name:         "1 byte",
			byteSize:     1,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(1),  // 2
			wantDecBytes: 1,
		},
		{
			name:         "16 bytes",
			byteSize:     16,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(16), // 22
			wantDecBytes: 16,
		},
		{
			name:         "32 bytes",
			byteSize:     32,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(32), // 43
			wantDecBytes: 32,
		},
		{
			name:         "64 bytes",
			byteSize:     64,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(64), // 86
			wantDecBytes: 64,
		},
		{
			name:         "93 bytes (just below max)",
			byteSize:     93,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(93), // 124
			wantDecBytes: 93,
		},
		{
			name:         "94 bytes (max)",
			byteSize:     94,
			wantEncLen:   base64.RawURLEncoding.EncodedLen(94), // 126
			wantDecBytes: 94,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := GenerateSecureToken(tt.byteSize, 0)
			require.NoError(t, err)
			assert.Len(t, token, tt.wantEncLen)

			decoded, err := base64.RawURLEncoding.DecodeString(token)
			require.NoError(t, err, "token must be decodable base64url")
			assert.Len(t, decoded, tt.wantDecBytes, "decoded length must match effective byte size")
		})
	}
}

// ---------------------------------------------------------------------------
// 3. stringLength: output must be exactly the requested character count
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_StringLength_Exact(t *testing.T) {
	t.Parallel()
	lengths := []int{1, 2, 10, 32, 43, 50, 64, 100, 125, 126}

	for _, want := range lengths {
		t.Run("len_"+itoa(want), func(t *testing.T) {
			t.Parallel()
			token, err := GenerateSecureToken(0, want)
			require.NoError(t, err)
			assert.Len(t, token, want, "output must be exactly %d chars", want)
		})
	}
}

func TestGenerateSecureToken_StringLength_IgnoresByteSize(t *testing.T) {
	t.Parallel()
	// When stringLength > 0 the byteSize argument is ignored.
	token, err := GenerateSecureToken(16, 50)
	require.NoError(t, err)
	assert.Len(t, token, 50, "stringLength must take priority over byteSize")
}

// ---------------------------------------------------------------------------
// 4. Max-size clamping (94 bytes / 126 encoded chars)
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_MaxClamping_ByteSize(t *testing.T) {
	t.Parallel()
	maxEncLen := base64.RawURLEncoding.EncodedLen(94) // 126

	for _, over := range []int{95, 100, 200, 1000} {
		t.Run("byteSize_"+itoa(over), func(t *testing.T) {
			t.Parallel()
			token, err := GenerateSecureToken(over, 0)
			require.NoError(t, err)
			assert.Len(t, token, maxEncLen,
				"byteSize %d must be clamped to 94 bytes → %d chars", over, maxEncLen)

			decoded, err := base64.RawURLEncoding.DecodeString(token)
			require.NoError(t, err)
			assert.Len(t, decoded, 94, "decoded bytes must be clamped to 94")
		})
	}
}

func TestGenerateSecureToken_MaxClamping_StringLength(t *testing.T) {
	t.Parallel()
	maxEncLen := base64.RawURLEncoding.EncodedLen(94) // 126

	for _, over := range []int{127, 128, 150, 256, 1000} {
		t.Run("stringLength_"+itoa(over), func(t *testing.T) {
			t.Parallel()
			token, err := GenerateSecureToken(0, over)
			require.NoError(t, err)
			assert.LessOrEqual(t, len(token), maxEncLen,
				"stringLength %d must be clamped; max output is %d chars", over, maxEncLen)
		})
	}
}

// ---------------------------------------------------------------------------
// 5. URL-safety: no padding, only base64url charset
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_URLSafe(t *testing.T) {
	t.Parallel()

	// Test across many sizes and iteration to catch any stray chars.
	configs := []struct {
		byteSize     int
		stringLength int
	}{
		{0, 0},
		{1, 0},
		{16, 0},
		{32, 0},
		{64, 0},
		{94, 0},
		{100, 0},  // clamped
		{0, 1},
		{0, 32},
		{0, 64},
		{0, 126},
		{0, 200}, // clamped
	}

	for _, cfg := range configs {
		for range 20 {
			token, err := GenerateSecureToken(cfg.byteSize, cfg.stringLength)
			require.NoError(t, err)

			assert.Regexp(t, base64URLCharset, token,
				"token must only contain base64url chars (A-Z a-z 0-9 - _)")
			assert.NotContains(t, token, "=",
				"token must not contain padding character '='")
			assert.NotContains(t, token, "+",
				"token must not contain standard-base64 char '+'")
			assert.NotContains(t, token, "/",
				"token must not contain standard-base64 char '/'")
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Uniqueness (statistical sanity check)
// ---------------------------------------------------------------------------

func TestGenerateSecureToken_Uniqueness(t *testing.T) {
	t.Parallel()
	const iterations = 1000
	tokens := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		token, err := GenerateSecureToken(32, 0)
		require.NoError(t, err)
		_, dup := tokens[token]
		assert.False(t, dup, "token collision detected")
		tokens[token] = struct{}{}
	}
	assert.Len(t, tokens, iterations, "all tokens must be unique")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkGenerateSecureToken_32Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(32, 0)
	}
}

func BenchmarkGenerateSecureToken_94Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(94, 0)
	}
}

func BenchmarkGenerateSecureToken_StringLen64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecureToken(0, 64)
	}
}

// itoa is a small helper to avoid importing strconv just for test names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
