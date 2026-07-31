package revocation

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowAllKeyResolver is a test helper that accepts unsigned tokens (alg: none).
type allowAllKeyResolver struct{}

func (allowAllKeyResolver) ResolveKey(_ context.Context, _, _ string) (any, error) {
	return jwt.UnsafeAllowNoneSignatureType, nil
}

func base64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestExtractStatusListReference(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://registry.example.com/statuslists/0",
					"idx": float64(42),
				},
			},
		}
		ref := ExtractStatusListReference(claims)
		require.NotNil(t, ref)
		assert.Equal(t, SchemeStatusList, ref.Scheme)
		assert.Equal(t, "https://registry.example.com/statuslists/0", ref.URI)
		assert.Equal(t, int64(42), ref.Index)
	})

	t.Run("no status claim", func(t *testing.T) {
		ref := ExtractStatusListReference(map[string]any{"iss": "x"})
		assert.Nil(t, ref)
	})

	t.Run("missing uri", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{"idx": float64(1)},
			},
		}
		assert.Nil(t, ExtractStatusListReference(claims))
	})
}

func TestRegistry_CheckStatus(t *testing.T) {
	t.Run("nil reference returns nil", func(t *testing.T) {
		r := NewRegistry()
		result, err := r.CheckStatus(t.Context(), nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("no checker for scheme", func(t *testing.T) {
		r := NewRegistry()
		_, err := r.CheckStatus(t.Context(), &Reference{Scheme: "unknown"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no checker registered")
	})
}

func TestRegistry_Validate(t *testing.T) {
	t.Run("no checkers returns nil", func(t *testing.T) {
		r := NewRegistry()
		result, err := r.Validate(t.Context(), map[string]any{"iss": "x"})
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("no status claim returns nil", func(t *testing.T) {
		statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
		checker, err := NewStatusListChecker(WithCache(statusCache), WithKeyResolver(allowAllKeyResolver{}))
		require.NoError(t, err)
		r := NewRegistry(checker)
		result, err := r.Validate(t.Context(), map[string]any{"iss": "x"})
		assert.NoError(t, err)
		assert.Nil(t, result, "credential without status is not revocable")
	})
}

func TestStatusListChecker_CheckStatus(t *testing.T) {
	// Create a test status list with entry 0=valid, 1=revoked, 2=suspended
	statuses := []uint8{tokenstatuslist.StatusValid, tokenstatuslist.StatusInvalid, tokenstatuslist.StatusSuspended}

	// Compress and encode to create a raw JWT payload (no signature verification in this test)
	encoded, err := tokenstatuslist.CompressAndEncode(statuses)
	require.NoError(t, err)

	// Build a minimal unsigned JWT (header.payload.signature) for testing
	payload := `{"iss":"https://registry.test","status_list":{"lst":"` + encoded + `"}}`
	fakeJWT := base64RawURL([]byte(`{"alg":"none"}`)) + "." + base64RawURL([]byte(payload)) + "."

	// Serve the status list token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(fakeJWT))
	}))
	defer server.Close()

	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithHTTPClient(server.Client()),
		// In production, the key resolver verifies the issuer's signature.
		// For testing, we use an allow-all resolver.
		WithKeyResolver(allowAllKeyResolver{}),
	)
	require.NoError(t, err)

	registry := NewRegistry(checker)

	t.Run("valid credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 0}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusValid, result.Status)
	})

	t.Run("revoked credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 1}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusInvalid, result.Status)
	})

	t.Run("suspended credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 2}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusSuspended, result.Status)
	})

	t.Run("index out of range", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 999}
		_, err := registry.CheckStatus(t.Context(), ref)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "out of range")
	})
}

func TestStatusListChecker_Unreachable(t *testing.T) {
	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithHTTPClient(&http.Client{Timeout: 1 * time.Second}),
		WithKeyResolver(allowAllKeyResolver{}),
	)
	require.NoError(t, err)

	ref := &Reference{Scheme: SchemeStatusList, URI: "http://192.0.2.1/unreachable", Index: 0}
	_, err = checker.CheckStatus(t.Context(), ref)
	assert.Error(t, err)
}

func TestStatusListChecker_Supports(t *testing.T) {
	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, _ := NewStatusListChecker(WithCache(statusCache), WithKeyResolver(allowAllKeyResolver{}))

	assert.True(t, checker.Supports(SchemeStatusList))
	assert.False(t, checker.Supports(Scheme("ocsp")))
}
