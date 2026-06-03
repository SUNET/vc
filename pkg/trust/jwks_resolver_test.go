package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockParseJWK is a test helper that extracts "kty" from the JWK map
// and returns a real ECDSA key as the parsed result.
func mockParseJWK(testKey crypto.PublicKey) func(jwkData any) (crypto.PublicKey, error) {
	return func(jwkData any) (crypto.PublicKey, error) {
		jwkMap, ok := jwkData.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected map, got %T", jwkData)
		}
		if _, ok := jwkMap["kty"]; !ok {
			return nil, fmt.Errorf("missing kty")
		}
		return testKey, nil
	}
}

func generateTestKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}

// newTestJWKS builds a JWKS JSON response with the given kid values.
func newTestJWKS(kids ...string) []byte {
	keys := make([]map[string]any, len(kids))
	for i, kid := range kids {
		keys[i] = map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"kid": kid,
			"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}
	}
	jwks := map[string]any{"keys": keys}
	data, _ := json.Marshal(jwks)
	return data
}

func TestJWKSKeyResolverResolveKeyByKID(t *testing.T) {
	testKey := generateTestKey(t)

	// Set up a test HTTP server serving JWT VC Issuer Metadata
	jwksData := newTestJWKS("key-1", "key-2", "key-3")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer":
			metadata := map[string]any{
				"issuer": serverURL,
				"jwks":   json.RawMessage(jwksData),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
		CacheTTL:            1 * time.Minute,
	})
	defer resolver.Stop()

	ctx := context.Background()

	t.Run("resolve existing kid", func(t *testing.T) {
		pubKey, jwkMap, err := resolver.ResolveKeyByKID(ctx, server.URL, "key-2")
		require.NoError(t, err)
		assert.Equal(t, testKey, pubKey)
		assert.Equal(t, "key-2", jwkMap["kid"])
		assert.Equal(t, "EC", jwkMap["kty"])
	})

	t.Run("kid not found", func(t *testing.T) {
		_, _, err := resolver.ResolveKeyByKID(ctx, server.URL, "nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no key found")
		assert.Contains(t, err.Error(), "nonexistent")
	})

	t.Run("cached on second call", func(t *testing.T) {
		// First call populates cache
		_, _, err := resolver.ResolveKeyByKID(ctx, server.URL, "key-1")
		require.NoError(t, err)
		assert.Equal(t, 1, resolver.Len()) // one issuer cached

		// Second call should use cache (server could be down)
		pubKey, jwkMap, err := resolver.ResolveKeyByKID(ctx, server.URL, "key-3")
		require.NoError(t, err)
		assert.Equal(t, testKey, pubKey)
		assert.Equal(t, "key-3", jwkMap["kid"])
	})

	t.Run("empty issuer URL", func(t *testing.T) {
		_, _, err := resolver.ResolveKeyByKID(ctx, "", "key-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer URL is empty")
	})

	t.Run("empty kid", func(t *testing.T) {
		_, _, err := resolver.ResolveKeyByKID(ctx, server.URL, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kid is empty")
	})
}

func TestJWKSKeyResolverJWKSURI(t *testing.T) {
	testKey := generateTestKey(t)
	jwksData := newTestJWKS("uri-key-1")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer":
			metadata := map[string]any{
				"issuer":   serverURL,
				"jwks_uri": serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata) // #nosec G104 //nolint:errcheck
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	pubKey, jwkMap, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "uri-key-1")
	require.NoError(t, err)
	assert.Equal(t, testKey, pubKey)
	assert.Equal(t, "uri-key-1", jwkMap["kid"])
}

func TestJWKSKeyResolverIssuerMismatch(t *testing.T) {
	testKey := generateTestKey(t)

	// All metadata endpoints return a wrong issuer — the entire chain should fail
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer":
			metadata := map[string]any{
				"issuer": "https://wrong-issuer.example.com",
				"jwks":   json.RawMessage(newTestJWKS("key-1")),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	_, _, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to discover JWKS")
}

func TestJWKSKeyResolverNoJWKSAnywhere(t *testing.T) {
	testKey := generateTestKey(t)

	// jwt-vc-issuer returns metadata with no jwks/jwks_uri, other endpoints 404
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer":
			metadata := map[string]any{
				"issuer": serverURL,
				// no jwks and no jwks_uri
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	_, _, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to discover JWKS")
}

func TestJWKSKeyResolverServerError(t *testing.T) {
	testKey := generateTestKey(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	_, _, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to discover JWKS")
}

func TestJWKSKeyResolverFallbackOAuthAS(t *testing.T) {
	// Simulates the vc project issuer: no jwt-vc-issuer endpoint,
	// but has openid-credential-issuer → authorization_servers → oauth-authorization-server → jwks_uri
	testKey := generateTestKey(t)
	jwksData := newTestJWKS("oauth-key-1")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer/":
			meta := map[string]any{
				"credential_issuer": serverURL,
				// no authorization_servers → defaults to issuer itself
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/.well-known/oauth-authorization-server":
			meta := map[string]any{
				"issuer":   serverURL,
				"jwks_uri": serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	pubKey, jwkMap, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "oauth-key-1")
	require.NoError(t, err)
	assert.Equal(t, testKey, pubKey)
	assert.Equal(t, "oauth-key-1", jwkMap["kid"])
}

func TestJWKSKeyResolverFallbackOIDCDiscovery(t *testing.T) {
	// No jwt-vc-issuer, no openid-credential-issuer; falls back to OIDC Discovery
	testKey := generateTestKey(t)
	jwksData := newTestJWKS("oidc-key-1")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			meta := map[string]any{
				"issuer":   serverURL,
				"jwks_uri": serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	pubKey, jwkMap, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "oidc-key-1")
	require.NoError(t, err)
	assert.Equal(t, testKey, pubKey)
	assert.Equal(t, "oidc-key-1", jwkMap["kid"])
}

func TestJWKSKeyResolverFallbackRFC8414(t *testing.T) {
	// No jwt-vc-issuer, no openid-credential-issuer, no openid-configuration;
	// falls back to .well-known/oauth-authorization-server (RFC 8414)
	testKey := generateTestKey(t)
	jwksData := newTestJWKS("rfc8414-key-1")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			meta := map[string]any{
				"issuer":   serverURL,
				"jwks_uri": serverURL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	pubKey, jwkMap, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "rfc8414-key-1")
	require.NoError(t, err)
	assert.Equal(t, testKey, pubKey)
	assert.Equal(t, "rfc8414-key-1", jwkMap["kid"])
}

func TestJWKSKeyResolverFallbackCredentialIssuerWithExplicitAS(t *testing.T) {
	// openid-credential-issuer specifies a separate authorization_servers URL
	testKey := generateTestKey(t)
	jwksData := newTestJWKS("as-key-1")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer/":
			meta := map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL + "/auth"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/.well-known/oauth-authorization-server/auth":
			// RFC 8615 §3: well-known suffix inserted between host and path
			meta := map[string]any{
				"issuer":   serverURL + "/auth",
				"jwks_uri": serverURL + "/auth/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(meta) // #nosec G104 //nolint:errcheck
		case "/auth/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData) // #nosec G104 //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	pubKey, jwkMap, err := resolver.ResolveKeyByKID(context.Background(), server.URL, "as-key-1")
	require.NoError(t, err)
	assert.Equal(t, testKey, pubKey)
	assert.Equal(t, "as-key-1", jwkMap["kid"])
}

func TestJWKSKeyResolverInvalidateIssuer(t *testing.T) {
	testKey := generateTestKey(t)
	callCount := 0

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		metadata := map[string]any{
			"issuer": serverURL,
			"jwks":   json.RawMessage(newTestJWKS("key-1")),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata) // #nosec G104 //nolint:errcheck
	}))
	serverURL = server.URL
	defer server.Close()

	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		HTTPClient:          server.Client(),
		ParseJWKToPublicKey: mockParseJWK(testKey),
		CacheTTL:            10 * time.Minute,
	})
	defer resolver.Stop()

	ctx := context.Background()

	// First call fetches
	_, _, err := resolver.ResolveKeyByKID(ctx, server.URL, "key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call uses cache
	_, _, err = resolver.ResolveKeyByKID(ctx, server.URL, "key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount) // still 1, no new fetch

	// Invalidate and re-fetch
	resolver.InvalidateIssuer(server.URL)
	_, _, err = resolver.ResolveKeyByKID(ctx, server.URL, "key-1")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount) // now 2, fetched again
}

func TestParseRawKeysEmptyArray(t *testing.T) {
	testKey := generateTestKey(t)
	resolver := NewJWKSKeyResolver(JWKSResolverConfig{
		ParseJWKToPublicKey: mockParseJWK(testKey),
	})
	defer resolver.Stop()

	// nil rawKeys
	result, err := resolver.parseRawKeys(nil)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS contains no keys")

	// empty rawKeys
	result, err = resolver.parseRawKeys([]json.RawMessage{})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS contains no keys")
}

func TestBuildWellKnownURL(t *testing.T) {
	tests := []struct {
		entity string
		suffix string
		want   string
	}{
		// Host-only
		{"https://example.com", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer"},
		// Trailing slash
		{"https://example.com/", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer"},
		// Path-based (RFC 8615 §3: insert between host and path)
		{"https://example.com/tenant1", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer/tenant1"},
		// Deep path
		{"https://example.com/org/tenant/v1", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer/org/tenant/v1"},
		// With port
		{"https://example.com:8443/tenant", "jwt-vc-issuer", "https://example.com:8443/.well-known/jwt-vc-issuer/tenant"},
		// HTTP (test servers)
		{"http://127.0.0.1:12345", "jwt-vc-issuer", "http://127.0.0.1:12345/.well-known/jwt-vc-issuer"},
	}

	for _, tt := range tests {
		t.Run(tt.entity, func(t *testing.T) {
			got := buildWellKnownURL(tt.entity, tt.suffix)
			assert.Equal(t, tt.want, got)
		})
	}
}
