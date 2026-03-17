package keyresolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

// TrustEvaluator validates whether a resolved key should be trusted
// This is separate from key resolution - it evaluates trust in name-to-key bindings
type TrustEvaluator interface {
	// EvaluateTrust checks if the given public key is authorized for the subject ID
	// Returns true if trusted, false otherwise
	EvaluateTrust(subjectID string, publicKey ed25519.PublicKey, role string) (bool, error)
}

// ECDSATrustEvaluator extends TrustEvaluator with ECDSA support
type ECDSATrustEvaluator interface {
	TrustEvaluator
	// EvaluateTrustECDSA checks if the given ECDSA public key is authorized
	EvaluateTrustECDSA(subjectID string, publicKey *ecdsa.PublicKey, role string) (bool, error)
}

// GoTrustEvaluator uses go-trust authzenclient for trust evaluation.
// This is the recommended implementation for new code.
type GoTrustEvaluator struct {
	client *authzenclient.Client
}

// NewGoTrustEvaluator creates a trust evaluator using go-trust authzenclient.
func NewGoTrustEvaluator(baseURL string) *GoTrustEvaluator {
	return &GoTrustEvaluator{
		client: authzenclient.New(baseURL),
	}
}

// NewGoTrustEvaluatorWithDiscovery creates a trust evaluator using AuthZEN discovery.
func NewGoTrustEvaluatorWithDiscovery(ctx context.Context, baseURL string) (*GoTrustEvaluator, error) {
	client, err := authzenclient.Discover(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("authzen discovery failed: %w", err)
	}
	return &GoTrustEvaluator{client: client}, nil
}

// NewGoTrustEvaluatorWithClient creates a trust evaluator with an existing client.
func NewGoTrustEvaluatorWithClient(client *authzenclient.Client) *GoTrustEvaluator {
	return &GoTrustEvaluator{client: client}
}

// EvaluateTrust validates the name-to-key binding via go-trust authzenclient.
func (g *GoTrustEvaluator) EvaluateTrust(subjectID string, publicKey ed25519.PublicKey, role string) (bool, error) {
	ctx := context.Background()
	return g.EvaluateTrustWithContext(ctx, subjectID, publicKey, role)
}

// EvaluateTrustWithContext validates trust with a provided context.
func (g *GoTrustEvaluator) EvaluateTrustWithContext(ctx context.Context, subjectID string, publicKey ed25519.PublicKey, role string) (bool, error) {
	jwk := Ed25519ToJWK(publicKey)

	var action *authzen.Action
	if role != "" {
		action = &authzen.Action{Name: role}
	}

	resp, err := g.client.EvaluateJWK(ctx, subjectID, jwk, action)
	if err != nil {
		return false, fmt.Errorf("trust evaluation failed: %w", err)
	}

	return resp.Decision, nil
}

// EvaluateTrustECDSA validates an ECDSA key binding.
func (g *GoTrustEvaluator) EvaluateTrustECDSA(subjectID string, publicKey *ecdsa.PublicKey, role string) (bool, error) {
	ctx := context.Background()
	return g.EvaluateTrustECDSAWithContext(ctx, subjectID, publicKey, role)
}

// EvaluateTrustECDSAWithContext validates an ECDSA key with context.
func (g *GoTrustEvaluator) EvaluateTrustECDSAWithContext(ctx context.Context, subjectID string, publicKey *ecdsa.PublicKey, role string) (bool, error) {
	jwk, err := ECDSAToJWK(publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to convert ECDSA key to JWK: %w", err)
	}

	var action *authzen.Action
	if role != "" {
		action = &authzen.Action{Name: role}
	}

	resp, err := g.client.EvaluateJWK(ctx, subjectID, jwk, action)
	if err != nil {
		return false, fmt.Errorf("trust evaluation failed: %w", err)
	}

	return resp.Decision, nil
}

// GetClient returns the underlying authzenclient.Client.
func (g *GoTrustEvaluator) GetClient() *authzenclient.Client {
	return g.client
}

// ValidatingResolver wraps a resolver with trust evaluation
// It first resolves the key, then validates it via a trust evaluator
type ValidatingResolver struct {
	resolver  Resolver
	evaluator TrustEvaluator
	role      string // Optional role to require
}

// NewValidatingResolver creates a resolver that validates trust after resolution
func NewValidatingResolver(resolver Resolver, evaluator TrustEvaluator, role string) *ValidatingResolver {
	return &ValidatingResolver{
		resolver:  resolver,
		evaluator: evaluator,
		role:      role,
	}
}

// ResolveEd25519 resolves the key and validates trust
func (v *ValidatingResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	// First, resolve the key
	key, err := v.resolver.ResolveEd25519(verificationMethod)
	if err != nil {
		return nil, err
	}

	// Extract DID from verification method for trust evaluation
	subjectID := ExtractDIDFromVerificationMethod(verificationMethod)

	// Then, validate trust
	trusted, err := v.evaluator.EvaluateTrust(subjectID, key, v.role)
	if err != nil {
		return nil, fmt.Errorf("trust evaluation failed: %w", err)
	}

	if !trusted {
		return nil, fmt.Errorf("key not trusted for %s", verificationMethod)
	}

	return key, nil
}

// ResolveECDSA resolves an ECDSA key and validates trust if possible.
func (v *ValidatingResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	// Check if the underlying resolver supports ECDSA
	ecdsaResolver, ok := v.resolver.(ECDSAResolver)
	if !ok {
		return nil, fmt.Errorf("underlying resolver does not support ECDSA")
	}

	// First, resolve the key
	key, err := ecdsaResolver.ResolveECDSA(verificationMethod)
	if err != nil {
		return nil, err
	}

	// Extract DID from verification method for trust evaluation
	subjectID := ExtractDIDFromVerificationMethod(verificationMethod)

	// Then, validate trust if evaluator supports ECDSA
	if ecdsaEvaluator, ok := v.evaluator.(ECDSATrustEvaluator); ok {
		trusted, err := ecdsaEvaluator.EvaluateTrustECDSA(subjectID, key, v.role)
		if err != nil {
			return nil, fmt.Errorf("ECDSA trust evaluation failed: %w", err)
		}

		if !trusted {
			return nil, fmt.Errorf("ECDSA key not trusted for %s", verificationMethod)
		}
	}
	// If evaluator doesn't support ECDSA, we skip trust evaluation
	// This allows using ValidatingResolver with Ed25519-only evaluators

	return key, nil
}
