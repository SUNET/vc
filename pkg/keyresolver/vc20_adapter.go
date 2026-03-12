package keyresolver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"

	"vc/pkg/openid4vp"
)

// VC20ResolverAdapter adapts the keyresolver interfaces to openid4vp.VC20KeyResolver.
// It wraps ECDSAResolver and can resolve both ECDSA and Ed25519 keys.
type VC20ResolverAdapter struct {
	resolver Resolver
}

// NewVC20ResolverAdapter creates an adapter that wraps a keyresolver.Resolver
// for use with openid4vp.VC20Handler.
func NewVC20ResolverAdapter(resolver Resolver) *VC20ResolverAdapter {
	return &VC20ResolverAdapter{resolver: resolver}
}

// ResolveKey implements openid4vp.VC20KeyResolver.
// It attempts ECDSA resolution first (if supported), then falls back to Ed25519.
func (a *VC20ResolverAdapter) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	// Try ECDSA first (most W3C VC Data Integrity credentials use ECDSA)
	if ecdsaResolver, ok := a.resolver.(ECDSAResolver); ok {
		key, err := ecdsaResolver.ResolveECDSA(verificationMethod)
		if err == nil {
			return key, nil
		}
		// Fall through to try Ed25519
	}

	// Try Ed25519
	key, err := a.resolver.ResolveEd25519(verificationMethod)
	if err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("could not resolve key for %s: no supported key type found", verificationMethod)
}

// Ensure VC20ResolverAdapter implements VC20KeyResolver
var _ openid4vp.VC20KeyResolver = (*VC20ResolverAdapter)(nil)

// ECDSAOnlyAdapter adapts ECDSAResolver to VC20KeyResolver for ECDSA-only resolution.
type ECDSAOnlyAdapter struct {
	resolver ECDSAResolver
}

// NewECDSAOnlyAdapter creates an adapter that only resolves ECDSA keys.
func NewECDSAOnlyAdapter(resolver ECDSAResolver) *ECDSAOnlyAdapter {
	return &ECDSAOnlyAdapter{resolver: resolver}
}

// ResolveKey implements openid4vp.VC20KeyResolver.
func (a *ECDSAOnlyAdapter) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	return a.resolver.ResolveECDSA(verificationMethod)
}

// Ensure ECDSAOnlyAdapter implements VC20KeyResolver
var _ openid4vp.VC20KeyResolver = (*ECDSAOnlyAdapter)(nil)

// Ed25519OnlyAdapter adapts Resolver to VC20KeyResolver for Ed25519-only resolution.
type Ed25519OnlyAdapter struct {
	resolver Resolver
}

// NewEd25519OnlyAdapter creates an adapter that only resolves Ed25519 keys.
func NewEd25519OnlyAdapter(resolver Resolver) *Ed25519OnlyAdapter {
	return &Ed25519OnlyAdapter{resolver: resolver}
}

// ResolveKey implements openid4vp.VC20KeyResolver.
func (a *Ed25519OnlyAdapter) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	return a.resolver.ResolveEd25519(verificationMethod)
}

// Ensure Ed25519OnlyAdapter implements VC20KeyResolver
var _ openid4vp.VC20KeyResolver = (*Ed25519OnlyAdapter)(nil)

// CompositeVC20Resolver combines multiple key resolution strategies.
type CompositeVC20Resolver struct {
	resolvers []openid4vp.VC20KeyResolver
}

// NewCompositeVC20Resolver creates a resolver that tries multiple resolvers in order.
func NewCompositeVC20Resolver(resolvers ...openid4vp.VC20KeyResolver) *CompositeVC20Resolver {
	return &CompositeVC20Resolver{resolvers: resolvers}
}

// ResolveKey tries each resolver until one succeeds.
func (c *CompositeVC20Resolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	var lastErr error

	for _, resolver := range c.resolvers {
		key, err := resolver.ResolveKey(ctx, verificationMethod)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all resolvers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no resolvers configured")
}

// Ensure CompositeVC20Resolver implements VC20KeyResolver
var _ openid4vp.VC20KeyResolver = (*CompositeVC20Resolver)(nil)

// TypedKeyResolver provides type-safe access to resolved keys.
type TypedKeyResolver struct {
	inner openid4vp.VC20KeyResolver
}

// NewTypedKeyResolver wraps a VC20KeyResolver with type-safe accessors.
func NewTypedKeyResolver(resolver openid4vp.VC20KeyResolver) *TypedKeyResolver {
	return &TypedKeyResolver{inner: resolver}
}

// ResolveKey implements VC20KeyResolver.
func (t *TypedKeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	return t.inner.ResolveKey(ctx, verificationMethod)
}

// ResolveECDSAKey resolves and returns an ECDSA key, or error if wrong type.
func (t *TypedKeyResolver) ResolveECDSAKey(ctx context.Context, verificationMethod string) (*ecdsa.PublicKey, error) {
	key, err := t.inner.ResolveKey(ctx, verificationMethod)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA key, got %T", key)
	}
	return ecdsaKey, nil
}

// ResolveEd25519Key resolves and returns an Ed25519 key, or error if wrong type.
func (t *TypedKeyResolver) ResolveEd25519Key(ctx context.Context, verificationMethod string) (ed25519.PublicKey, error) {
	key, err := t.inner.ResolveKey(ctx, verificationMethod)
	if err != nil {
		return nil, err
	}

	ed25519Key, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 key, got %T", key)
	}
	return ed25519Key, nil
}

// Ensure TypedKeyResolver implements VC20KeyResolver
var _ openid4vp.VC20KeyResolver = (*TypedKeyResolver)(nil)
