//go:build vc20
// +build vc20

package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"vc/pkg/openid4vp"
)

// mockResolver implements both Resolver and ECDSAResolver for testing
type mockResolver struct {
	ed25519Key    ed25519.PublicKey
	ecdsaKey      *ecdsa.PublicKey
	ed25519Err    error
	ecdsaErr      error
	supportsECDSA bool
}

func (m *mockResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	if m.ed25519Err != nil {
		return nil, m.ed25519Err
	}
	return m.ed25519Key, nil
}

func (m *mockResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	if m.ecdsaErr != nil {
		return nil, m.ecdsaErr
	}
	return m.ecdsaKey, nil
}

// ed25519OnlyMockResolver implements only Resolver (not ECDSAResolver)
type ed25519OnlyMockResolver struct {
	key ed25519.PublicKey
	err error
}

func (m *ed25519OnlyMockResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}

// TestVC20ResolverAdapter_Interface verifies interface compliance
func TestVC20ResolverAdapter_Interface(t *testing.T) {
	var _ openid4vp.VC20KeyResolver = (*VC20ResolverAdapter)(nil)
	var _ openid4vp.VC20KeyResolver = (*ECDSAOnlyAdapter)(nil)
	var _ openid4vp.VC20KeyResolver = (*Ed25519OnlyAdapter)(nil)
	var _ openid4vp.VC20KeyResolver = (*CompositeVC20Resolver)(nil)
	var _ openid4vp.VC20KeyResolver = (*TypedKeyResolver)(nil)
}

// TestVC20ResolverAdapter_ResolveKey_ECDSA tests ECDSA key resolution
func TestVC20ResolverAdapter_ResolveKey_ECDSA(t *testing.T) {
	// Generate test ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mock := &mockResolver{
		ecdsaKey:      &ecdsaKey.PublicKey,
		supportsECDSA: true,
	}
	adapter := NewVC20ResolverAdapter(mock)

	key, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolvedKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	if resolvedKey.X.Cmp(ecdsaKey.PublicKey.X) != 0 || resolvedKey.Y.Cmp(ecdsaKey.PublicKey.Y) != 0 {
		t.Error("resolved key does not match expected key")
	}
}

// TestVC20ResolverAdapter_ResolveKey_Ed25519 tests Ed25519 key resolution
func TestVC20ResolverAdapter_ResolveKey_Ed25519(t *testing.T) {
	// Generate test Ed25519 key
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	mock := &ed25519OnlyMockResolver{
		key: ed25519PubKey,
	}
	adapter := NewVC20ResolverAdapter(mock)

	key, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolvedKey, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", key)
	}

	if !resolvedKey.Equal(ed25519PubKey) {
		t.Error("resolved key does not match expected key")
	}
}

// TestVC20ResolverAdapter_ResolveKey_ECDSAFallsBackToEd25519 tests fallback behavior
func TestVC20ResolverAdapter_ResolveKey_ECDSAFallsBackToEd25519(t *testing.T) {
	// Generate test Ed25519 key
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	mock := &mockResolver{
		ed25519Key:    ed25519PubKey,
		ecdsaErr:      errors.New("ECDSA not supported for this DID"),
		supportsECDSA: true,
	}
	adapter := NewVC20ResolverAdapter(mock)

	key, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolvedKey, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey after fallback, got %T", key)
	}

	if !resolvedKey.Equal(ed25519PubKey) {
		t.Error("resolved key does not match expected key")
	}
}

// TestVC20ResolverAdapter_ResolveKey_BothFail tests when both key types fail
func TestVC20ResolverAdapter_ResolveKey_BothFail(t *testing.T) {
	mock := &mockResolver{
		ecdsaErr:      errors.New("ECDSA resolution failed"),
		ed25519Err:    errors.New("Ed25519 resolution failed"),
		supportsECDSA: true,
	}
	adapter := NewVC20ResolverAdapter(mock)

	_, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err == nil {
		t.Error("expected error when both key types fail")
	}
}

// TestECDSAOnlyAdapter tests ECDSAOnlyAdapter
func TestECDSAOnlyAdapter(t *testing.T) {
	// Generate test ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mock := &mockResolver{
		ecdsaKey: &ecdsaKey.PublicKey,
	}
	adapter := NewECDSAOnlyAdapter(mock)

	key, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolvedKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	if resolvedKey.X.Cmp(ecdsaKey.PublicKey.X) != 0 {
		t.Error("resolved key does not match expected key")
	}
}

// TestEd25519OnlyAdapter tests Ed25519OnlyAdapter
func TestEd25519OnlyAdapter(t *testing.T) {
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	mock := &ed25519OnlyMockResolver{
		key: ed25519PubKey,
	}
	adapter := NewEd25519OnlyAdapter(mock)

	key, err := adapter.ResolveKey(t.Context(), "did:example:issuer#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resolvedKey, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", key)
	}

	if !resolvedKey.Equal(ed25519PubKey) {
		t.Error("resolved key does not match expected key")
	}
}

// TestCompositeVC20Resolver tests CompositeVC20Resolver
func TestCompositeVC20Resolver(t *testing.T) {
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	t.Run("first resolver succeeds", func(t *testing.T) {
		resolver1 := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{key: ed25519PubKey})
		resolver2 := NewECDSAOnlyAdapter(&mockResolver{ecdsaKey: &ecdsaKey.PublicKey})

		composite := NewCompositeVC20Resolver(resolver1, resolver2)

		key, err := composite.ResolveKey(t.Context(), "did:example:issuer#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := key.(ed25519.PublicKey); !ok {
			t.Errorf("expected Ed25519 key from first resolver, got %T", key)
		}
	})

	t.Run("fallback to second resolver", func(t *testing.T) {
		resolver1 := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{err: errors.New("not found")})
		resolver2 := NewECDSAOnlyAdapter(&mockResolver{ecdsaKey: &ecdsaKey.PublicKey})

		composite := NewCompositeVC20Resolver(resolver1, resolver2)

		key, err := composite.ResolveKey(t.Context(), "did:example:issuer#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := key.(*ecdsa.PublicKey); !ok {
			t.Errorf("expected ECDSA key from second resolver, got %T", key)
		}
	})

	t.Run("all resolvers fail", func(t *testing.T) {
		resolver1 := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{err: errors.New("not found 1")})
		resolver2 := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{err: errors.New("not found 2")})

		composite := NewCompositeVC20Resolver(resolver1, resolver2)

		_, err := composite.ResolveKey(t.Context(), "did:example:issuer#key-1")
		if err == nil {
			t.Error("expected error when all resolvers fail")
		}
	})

	t.Run("no resolvers configured", func(t *testing.T) {
		composite := NewCompositeVC20Resolver()

		_, err := composite.ResolveKey(t.Context(), "did:example:issuer#key-1")
		if err == nil {
			t.Error("expected error when no resolvers configured")
		}
	})
}

// TestTypedKeyResolver tests TypedKeyResolver
func TestTypedKeyResolver(t *testing.T) {
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	t.Run("ResolveECDSAKey success", func(t *testing.T) {
		inner := NewECDSAOnlyAdapter(&mockResolver{ecdsaKey: &ecdsaKey.PublicKey})
		typed := NewTypedKeyResolver(inner)

		key, err := typed.ResolveECDSAKey(t.Context(), "did:example:issuer#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.X.Cmp(ecdsaKey.PublicKey.X) != 0 {
			t.Error("resolved key does not match expected key")
		}
	})

	t.Run("ResolveECDSAKey wrong type", func(t *testing.T) {
		inner := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{key: ed25519PubKey})
		typed := NewTypedKeyResolver(inner)

		_, err := typed.ResolveECDSAKey(t.Context(), "did:example:issuer#key-1")
		if err == nil {
			t.Error("expected error when resolving Ed25519 key as ECDSA")
		}
	})

	t.Run("ResolveEd25519Key success", func(t *testing.T) {
		inner := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{key: ed25519PubKey})
		typed := NewTypedKeyResolver(inner)

		key, err := typed.ResolveEd25519Key(t.Context(), "did:example:issuer#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !key.Equal(ed25519PubKey) {
			t.Error("resolved key does not match expected key")
		}
	})

	t.Run("ResolveEd25519Key wrong type", func(t *testing.T) {
		inner := NewECDSAOnlyAdapter(&mockResolver{ecdsaKey: &ecdsaKey.PublicKey})
		typed := NewTypedKeyResolver(inner)

		_, err := typed.ResolveEd25519Key(t.Context(), "did:example:issuer#key-1")
		if err == nil {
			t.Error("expected error when resolving ECDSA key as Ed25519")
		}
	})

	t.Run("ResolveKey passthrough", func(t *testing.T) {
		inner := NewEd25519OnlyAdapter(&ed25519OnlyMockResolver{key: ed25519PubKey})
		typed := NewTypedKeyResolver(inner)

		key, err := typed.ResolveKey(t.Context(), "did:example:issuer#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := key.(ed25519.PublicKey); !ok {
			t.Errorf("expected ed25519.PublicKey, got %T", key)
		}
	})
}

// TestVC20ResolverAdapter_WithLocalResolver tests integration with LocalResolver
func TestVC20ResolverAdapter_WithLocalResolver(t *testing.T) {
	localResolver := NewLocalResolver()
	adapter := NewVC20ResolverAdapter(localResolver)

	// Test with did:jwk containing Ed25519 key
	// Create a valid did:jwk
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	_ = ed25519PubKey // Will be used in actual did:jwk test

	// Test with invalid DID - should return error
	_, err = adapter.ResolveKey(t.Context(), "did:example:unknown")
	if err == nil {
		t.Error("expected error for unsupported DID method")
	}
}

// TestVC20ResolverAdapter_WithSmartResolver tests the full wiring
func TestVC20ResolverAdapter_WithSmartResolver(t *testing.T) {
	// Create a mock remote resolver
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mockRemote := &mockResolver{
		ed25519Key:    ed25519PubKey,
		ecdsaKey:      &ecdsaKey.PublicKey,
		supportsECDSA: true,
	}

	// Create SmartResolver with mock remote
	smartResolver := NewSmartResolver(mockRemote)

	// Create VC20ResolverAdapter wrapping SmartResolver
	adapter := NewVC20ResolverAdapter(smartResolver)

	// Test resolution of non-local DID (should use mock remote)
	key, err := adapter.ResolveKey(t.Context(), "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should resolve to ECDSA key (tried first by adapter)
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected ECDSA key from SmartResolver, got %T", key)
	}
}

// TestVC20ResolverAdapter_WithVC20Handler shows complete integration
func TestVC20ResolverAdapter_WithVC20Handler_Integration(t *testing.T) {
	// This test demonstrates the full wiring:
	// SmartResolver -> VC20ResolverAdapter -> VC20Handler

	// Create mock resolver with ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mockRemote := &mockResolver{
		ecdsaKey:      &ecdsaKey.PublicKey,
		supportsECDSA: true,
	}

	// Build the chain: SmartResolver -> VC20ResolverAdapter
	smartResolver := NewSmartResolver(mockRemote)
	vc20Resolver := NewVC20ResolverAdapter(smartResolver)

	// Create VC20Handler with our resolver
	handler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20KeyResolver(vc20Resolver),
		openid4vp.WithVC20TrustedIssuers([]string{"did:web:example.com"}),
	)
	if err != nil {
		t.Fatalf("failed to create VC20Handler: %v", err)
	}

	// The handler should now be configured with our resolver chain
	if handler == nil {
		t.Error("handler should not be nil")
	}

	// Note: Full credential verification would require creating a signed credential
	// This test verifies the wiring is correct
	t.Log("Integration wiring complete: SmartResolver -> VC20ResolverAdapter -> VC20Handler")
}
