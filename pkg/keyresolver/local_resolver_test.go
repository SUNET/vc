//go:build vc20

package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCanResolveLocally(t *testing.T) {
	tests := []struct {
		name     string
		vm       string
		expected bool
	}{
		{"did:key", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", true},
		{"did:key with fragment", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", true},
		{"did:jwk", "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcWYzX3drSENiVEFkRGRYTXVRNV9SeVpxYk5GaG1SVHAwTk9acFBLVW8ifQ", true},
		{"did:web", "did:web:example.com#key-1", false},
		{"did:ebsi", "did:ebsi:z24KSXY8SQfPDiJ9JwPnYxVQ#key-1", false},
		{"multikey z prefix", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", true},
		{"multikey u prefix", "uMQAAAQ", true},
		{"https URL", "https://example.com/keys/1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanResolveLocally(tt.vm)
			if result != tt.expected {
				t.Errorf("CanResolveLocally(%q) = %v, want %v", tt.vm, result, tt.expected)
			}
		})
	}
}

func TestLocalResolver_DidJwk_Ed25519(t *testing.T) {
	// Generate a test Ed25519 key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWK
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey),
	}

	// Encode as did:jwk
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	// Resolve
	resolver := NewLocalResolver()
	resolved, err := resolver.ResolveEd25519(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve did:jwk: %v", err)
	}

	if !pubKey.Equal(resolved) {
		t.Error("resolved key doesn't match original")
	}
}

func TestLocalResolver_DidJwk_Ed25519_WithFragment(t *testing.T) {
	// Generate a test Ed25519 key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWK
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey),
	}

	// Encode as did:jwk with fragment
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	encodedJwk := base64.RawURLEncoding.EncodeToString(jwkBytes)
	didJwk := "did:jwk:" + encodedJwk + "#0"

	// Resolve
	resolver := NewLocalResolver()
	resolved, err := resolver.ResolveEd25519(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve did:jwk with fragment: %v", err)
	}

	if !pubKey.Equal(resolved) {
		t.Error("resolved key doesn't match original")
	}
}

func TestLocalResolver_DidJwk_ECDSA_P256(t *testing.T) {
	// Generate a test P-256 key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Create JWK
	jwk, err := ECDSAToJWK(pubKey)
	if err != nil {
		t.Fatalf("failed to convert to JWK: %v", err)
	}

	// Encode as did:jwk
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	// Resolve
	resolver := NewLocalResolver()
	resolved, err := resolver.ResolveECDSA(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve did:jwk ECDSA: %v", err)
	}

	// Compare keys
	if pubKey.X.Cmp(resolved.X) != 0 || pubKey.Y.Cmp(resolved.Y) != 0 {
		t.Error("resolved ECDSA key doesn't match original")
	}
}

func TestLocalResolver_DidJwk_ECDSA_P384(t *testing.T) {
	// Generate a test P-384 key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// Create JWK
	jwk, err := ECDSAToJWK(pubKey)
	if err != nil {
		t.Fatalf("failed to convert to JWK: %v", err)
	}

	// Encode as did:jwk
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	// Resolve
	resolver := NewLocalResolver()
	resolved, err := resolver.ResolveECDSA(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve did:jwk ECDSA P-384: %v", err)
	}

	// Compare keys
	if pubKey.X.Cmp(resolved.X) != 0 || pubKey.Y.Cmp(resolved.Y) != 0 {
		t.Error("resolved ECDSA P-384 key doesn't match original")
	}
}

func TestLocalResolver_DidJwk_InvalidBase64(t *testing.T) {
	resolver := NewLocalResolver()

	// Invalid base64
	_, err := resolver.ResolveEd25519("did:jwk:not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestLocalResolver_DidJwk_InvalidJSON(t *testing.T) {
	resolver := NewLocalResolver()

	// Valid base64 but invalid JSON
	invalidJson := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := resolver.ResolveEd25519("did:jwk:" + invalidJson)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLocalResolver_DidJwk_WrongKeyType(t *testing.T) {
	resolver := NewLocalResolver()

	// Create an ECDSA JWK but try to resolve as Ed25519
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	jwk, _ := ECDSAToJWK(&privKey.PublicKey)
	jwkBytes, _ := json.Marshal(jwk)
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	_, err = resolver.ResolveEd25519(didJwk)
	if err == nil {
		t.Error("expected error when resolving ECDSA key as Ed25519")
	}
}

func TestLocalResolver_DidJwk_Empty(t *testing.T) {
	resolver := NewLocalResolver()

	_, err := resolver.ResolveEd25519("did:jwk:")
	if err == nil {
		t.Error("expected error for empty did:jwk")
	}
}

// Test the existing did:key functionality still works
func TestLocalResolver_DidKey_Ed25519(t *testing.T) {
	// Known test vector: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
	// This is a well-known Ed25519 did:key test vector
	didKey := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	resolver := NewLocalResolver()
	key, err := resolver.ResolveEd25519(didKey)
	if err != nil {
		t.Fatalf("failed to resolve did:key: %v", err)
	}

	// Should return a 32-byte Ed25519 public key
	if len(key) != ed25519.PublicKeySize {
		t.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(key))
	}
}

func TestLocalResolver_UnsupportedMethod(t *testing.T) {
	resolver := NewLocalResolver()

	// did:web requires external resolution
	_, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Error("expected error for unsupported did:web")
	}
}

// RoundTrip test: generate key -> create did:jwk -> resolve -> compare
func TestLocalResolver_DidJwk_RoundTrip(t *testing.T) {
	resolver := NewLocalResolver()

	t.Run("Ed25519", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		jwk := Ed25519ToJWK(pubKey)
		jwkBytes, _ := json.Marshal(jwk)
		didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

		resolved, err := resolver.ResolveEd25519(didJwk)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if !pubKey.Equal(resolved) {
			t.Error("round-trip key mismatch")
		}
	})

	t.Run("ECDSA-P256", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey := &privKey.PublicKey
		jwk, _ := ECDSAToJWK(pubKey)
		jwkBytes, _ := json.Marshal(jwk)
		didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

		resolved, err := resolver.ResolveECDSA(didJwk)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if pubKey.X.Cmp(resolved.X) != 0 || pubKey.Y.Cmp(resolved.Y) != 0 {
			t.Error("round-trip key mismatch")
		}
	})

	t.Run("ECDSA-P384", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		pubKey := &privKey.PublicKey
		jwk, _ := ECDSAToJWK(pubKey)
		jwkBytes, _ := json.Marshal(jwk)
		didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

		resolved, err := resolver.ResolveECDSA(didJwk)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if pubKey.X.Cmp(resolved.X) != 0 || pubKey.Y.Cmp(resolved.Y) != 0 {
			t.Error("round-trip key mismatch")
		}
	})
}

// SmartResolver tests

// mockRemoteResolver is a mock resolver for testing SmartResolver routing
type mockRemoteResolver struct {
	ed25519Key ed25519.PublicKey
	ecdsaKey   *ecdsa.PublicKey
	called     bool
}

func (m *mockRemoteResolver) ResolveEd25519(vm string) (ed25519.PublicKey, error) {
	m.called = true
	if m.ed25519Key == nil {
		return nil, fmt.Errorf("key not found: %s", vm)
	}
	return m.ed25519Key, nil
}

func (m *mockRemoteResolver) ResolveECDSA(vm string) (*ecdsa.PublicKey, error) {
	m.called = true
	if m.ecdsaKey == nil {
		return nil, fmt.Errorf("ECDSA key not found: %s", vm)
	}
	return m.ecdsaKey, nil
}

func TestSmartResolver_RoutesToLocal_DidKey(t *testing.T) {
	remoteKey, _, _ := ed25519.GenerateKey(rand.Reader)
	remote := &mockRemoteResolver{ed25519Key: remoteKey}
	smart := NewSmartResolver(remote)

	// Resolve a did:key - should use local resolver, not remote
	didKey := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	_, err := smart.ResolveEd25519(didKey)
	if err != nil {
		t.Fatalf("failed to resolve did:key: %v", err)
	}

	if remote.called {
		t.Error("remote resolver was called for did:key - should use local")
	}
}

func TestSmartResolver_RoutesToLocal_DidJwk(t *testing.T) {
	remoteKey, _, _ := ed25519.GenerateKey(rand.Reader)
	remote := &mockRemoteResolver{ed25519Key: remoteKey}
	smart := NewSmartResolver(remote)

	// Create a did:jwk
	localKey, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := Ed25519ToJWK(localKey)
	jwkBytes, _ := json.Marshal(jwk)
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	resolved, err := smart.ResolveEd25519(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve did:jwk: %v", err)
	}

	if remote.called {
		t.Error("remote resolver was called for did:jwk - should use local")
	}

	if !localKey.Equal(resolved) {
		t.Error("resolved key doesn't match the key in did:jwk")
	}
}

func TestSmartResolver_RoutesToRemote_DidWeb(t *testing.T) {
	remoteKey, _, _ := ed25519.GenerateKey(rand.Reader)
	remote := &mockRemoteResolver{ed25519Key: remoteKey}
	smart := NewSmartResolver(remote)

	resolved, err := smart.ResolveEd25519("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve did:web: %v", err)
	}

	if !remote.called {
		t.Error("remote resolver was NOT called for did:web - should use remote")
	}

	if !remoteKey.Equal(resolved) {
		t.Error("resolved key doesn't match remote key")
	}
}

func TestSmartResolver_RoutesToRemote_DidEbsi(t *testing.T) {
	remoteKey, _, _ := ed25519.GenerateKey(rand.Reader)
	remote := &mockRemoteResolver{ed25519Key: remoteKey}
	smart := NewSmartResolver(remote)

	_, err := smart.ResolveEd25519("did:ebsi:z24KSXY8SQfPDiJ9JwPnYxVQ#key-1")
	if err != nil {
		t.Fatalf("failed to resolve did:ebsi: %v", err)
	}

	if !remote.called {
		t.Error("remote resolver was NOT called for did:ebsi - should use remote")
	}
}

func TestSmartResolver_ECDSA_Local(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	remoteKey := &privKey.PublicKey
	remote := &mockRemoteResolver{ecdsaKey: remoteKey}
	smart := NewSmartResolver(remote)

	// Create a did:jwk with ECDSA key
	localPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	localKey := &localPriv.PublicKey
	jwk, _ := ECDSAToJWK(localKey)
	jwkBytes, _ := json.Marshal(jwk)
	didJwk := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	resolved, err := smart.ResolveECDSA(didJwk)
	if err != nil {
		t.Fatalf("failed to resolve ECDSA did:jwk: %v", err)
	}

	if remote.called {
		t.Error("remote resolver was called for did:jwk ECDSA - should use local")
	}

	if localKey.X.Cmp(resolved.X) != 0 || localKey.Y.Cmp(resolved.Y) != 0 {
		t.Error("resolved ECDSA key doesn't match local key")
	}
}

func TestSmartResolver_ECDSA_Remote(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	remoteKey := &privKey.PublicKey
	remote := &mockRemoteResolver{ecdsaKey: remoteKey}
	smart := NewSmartResolver(remote)

	resolved, err := smart.ResolveECDSA("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve ECDSA did:web: %v", err)
	}

	if !remote.called {
		t.Error("remote resolver was NOT called for did:web ECDSA - should use remote")
	}

	if remoteKey.X.Cmp(resolved.X) != 0 || remoteKey.Y.Cmp(resolved.Y) != 0 {
		t.Error("resolved ECDSA key doesn't match remote key")
	}
}

func TestSmartResolver_GetResolvers(t *testing.T) {
	remote := &mockRemoteResolver{}
	smart := NewSmartResolver(remote)

	if smart.GetLocalResolver() == nil {
		t.Error("GetLocalResolver returned nil")
	}

	if smart.GetRemoteResolver() != remote {
		t.Error("GetRemoteResolver returned wrong resolver")
	}
}

// Factory function tests

func TestNewResolverFromConfig_NoPDP(t *testing.T) {
	cfg := ResolverConfig{
		PDPURL: "",
	}

	resolver, err := NewResolverFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be LocalResolver
	_, ok := resolver.(*LocalResolver)
	if !ok {
		t.Errorf("expected LocalResolver, got %T", resolver)
	}

	// Should be able to resolve did:key
	didKey := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	_, err = resolver.ResolveEd25519(didKey)
	if err != nil {
		t.Errorf("should resolve did:key locally: %v", err)
	}
}

func TestNewResolverFromConfig_WithPDP(t *testing.T) {
	cfg := ResolverConfig{
		PDPURL: "https://trust.example.com/pdp",
	}

	resolver, err := NewResolverFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be SmartResolver
	smart, ok := resolver.(*SmartResolver)
	if !ok {
		t.Errorf("expected SmartResolver, got %T", resolver)
	}

	// Local should work
	if smart.GetLocalResolver() == nil {
		t.Error("SmartResolver should have local resolver")
	}
}

func TestResolverConfig_GetPDPURL(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ResolverConfig
		expected string
	}{
		{
			name:     "returns PDPURL when set",
			cfg:      ResolverConfig{PDPURL: "https://pdp.example.com"},
			expected: "https://pdp.example.com",
		},
		{
			name:     "empty when not set",
			cfg:      ResolverConfig{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetPDPURL()
			if got != tt.expected {
				t.Errorf("GetPDPURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewResolverWithPDP(t *testing.T) {
	smart := NewResolverWithPDP("https://trust.example.com/pdp")

	if smart == nil {
		t.Fatal("NewResolverWithPDP returned nil")
	}

	if smart.GetLocalResolver() == nil {
		t.Error("missing local resolver")
	}

	if smart.GetRemoteResolver() == nil {
		t.Error("missing remote resolver")
	}
}

func TestNewLocalOnlyResolver(t *testing.T) {
	resolver := NewLocalOnlyResolver()

	if resolver == nil {
		t.Fatal("NewLocalOnlyResolver returned nil")
	}

	// Should resolve did:key
	didKey := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	_, err := resolver.ResolveEd25519(didKey)
	if err != nil {
		t.Errorf("should resolve did:key: %v", err)
	}
}
