package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

// GoTrustEvaluator implements TrustEvaluator using go-trust AuthZEN client.
// It can validate both JWK and x5c key types against a Policy Decision Point.
type GoTrustEvaluator struct {
	client *authzenclient.Client
}

// NewTrustEvaluatorFromConfig creates the appropriate TrustEvaluator based on configuration.
// If pdpURL is empty, returns an AllowAllEvaluator (trusted=true for all requests).
// If pdpURL is set, returns a GoTrustEvaluator that queries the PDP for trust decisions.
//
// This provides harmonized trust management across applications:
//   - Empty PDP URL: "allow all" mode - resolved keys are always considered trusted
//   - Non-empty PDP URL: "default deny" mode - trust decisions require PDP approval
func NewTrustEvaluatorFromConfig(pdpURL string) TrustEvaluator {
	if pdpURL == "" {
		return NewAllowAllEvaluator()
	}
	return NewGoTrustEvaluator(pdpURL)
}

// NewGoTrustEvaluator creates a trust evaluator using go-trust with a known PDP URL.
func NewGoTrustEvaluator(pdpURL string) *GoTrustEvaluator {
	client := authzenclient.New(pdpURL)
	return &GoTrustEvaluator{client: client}
}

// NewGoTrustEvaluatorWithDiscovery creates a trust evaluator using AuthZEN discovery.
func NewGoTrustEvaluatorWithDiscovery(ctx context.Context, baseURL string) (*GoTrustEvaluator, error) {
	client, err := authzenclient.Discover(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("authzen discovery failed: %w", err)
	}
	return &GoTrustEvaluator{client: client}, nil
}

// NewGoTrustEvaluatorWithClient creates a trust evaluator with a pre-configured client.
func NewGoTrustEvaluatorWithClient(client *authzenclient.Client) *GoTrustEvaluator {
	return &GoTrustEvaluator{client: client}
}

// Evaluate implements TrustEvaluator.
func (e *GoTrustEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if req == nil {
		return nil, fmt.Errorf("%s", ErrMsgNilRequest)
	}

	var authzenReq *authzen.EvaluationRequest
	var err error

	switch req.KeyType {
	case KeyTypeJWK:
		authzenReq, err = e.buildJWKRequest(req)
	case KeyTypeX5C:
		authzenReq, err = e.buildX5CRequest(req)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to build evaluation request: %w", err)
	}

	resp, err := e.client.Evaluate(ctx, authzenReq)
	if err != nil {
		return nil, fmt.Errorf("trust evaluation failed: %w", err)
	}

	decision := &TrustDecision{
		Trusted: resp.Decision,
	}

	// Extract reason and metadata from response context
	if resp.Context != nil {
		if resp.Context.Reason != nil {
			if userReason, ok := resp.Context.Reason["user"].(string); ok {
				decision.Reason = userReason
			} else if adminReason, ok := resp.Context.Reason["admin"].(string); ok {
				decision.Reason = adminReason
			}
		}
		decision.Metadata = resp.Context.TrustMetadata

		// Try to extract trust framework from metadata
		if meta, ok := resp.Context.TrustMetadata.(map[string]any); ok {
			if tf, ok := meta["trust_framework"].(string); ok {
				decision.TrustFramework = tf
			}
		}
	}

	return decision, nil
}

// SupportsKeyType implements TrustEvaluator.
func (e *GoTrustEvaluator) SupportsKeyType(kt KeyType) bool {
	return kt == KeyTypeJWK || kt == KeyTypeX5C
}

// buildJWKRequest builds an AuthZEN request for JWK validation.
func (e *GoTrustEvaluator) buildJWKRequest(req *EvaluationRequest) (*authzen.EvaluationRequest, error) {
	var jwk map[string]any

	switch k := req.Key.(type) {
	case map[string]any:
		jwk = k
	case *ecdsa.PublicKey:
		var err error
		jwk, err = ecdsaToJWK(k)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ECDSA key to JWK: %w", err)
		}
	case ed25519.PublicKey:
		jwk = ed25519ToJWK(k)
	case crypto.PublicKey:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	default:
		return nil, fmt.Errorf("invalid key type for JWK: %T", req.Key)
	}

	authzenReq := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   req.SubjectID,
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   req.SubjectID,
			Key:  []any{jwk},
		},
	}

	// Use GetEffectiveAction for policy-based routing
	if action := req.GetEffectiveAction(); action != "" {
		authzenReq.Action = &authzen.Action{Name: action}
	}

	// Add context from TrustOptions
	e.addContextOptions(authzenReq, req.Options)

	return authzenReq, nil
}

// buildX5CRequest builds an AuthZEN request for x5c certificate chain validation.
func (e *GoTrustEvaluator) buildX5CRequest(req *EvaluationRequest) (*authzen.EvaluationRequest, error) {
	var certStrings []string

	switch k := req.Key.(type) {
	case []*x509.Certificate:
		chain := X5CCertChain(k)
		certStrings = chain.ToBase64Strings()
	case X5CCertChain:
		certStrings = k.ToBase64Strings()
	case []string:
		certStrings = k
	default:
		return nil, fmt.Errorf("invalid key type for x5c: %T", req.Key)
	}

	// Convert to []any for AuthZEN
	keys := make([]any, len(certStrings))
	for i, cert := range certStrings {
		keys[i] = cert
	}

	authzenReq := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   req.SubjectID,
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   req.SubjectID,
			Key:  keys,
		},
	}

	// Use GetEffectiveAction for policy-based routing
	if action := req.GetEffectiveAction(); action != "" {
		authzenReq.Action = &authzen.Action{Name: action}
	}

	// Add context from TrustOptions
	e.addContextOptions(authzenReq, req.Options)

	return authzenReq, nil
}

// ResolveKey implements KeyResolver for DID-based resolution.
func (e *GoTrustEvaluator) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	resp, err := e.client.Resolve(ctx, verificationMethod)
	if err != nil {
		return nil, fmt.Errorf("resolution request failed: %w", err)
	}

	if !resp.Decision {
		reason := "unknown"
		if resp.Context != nil && resp.Context.Reason != nil {
			if r, ok := resp.Context.Reason["error"].(string); ok {
				reason = r
			}
		}
		return nil, fmt.Errorf("resolution denied for %s: %s", verificationMethod, reason)
	}

	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		return nil, fmt.Errorf("no trust_metadata in response for %s", verificationMethod)
	}

	// Extract key from trust metadata (DID document)
	return extractKeyFromMetadata(resp.Context.TrustMetadata, verificationMethod)
}

// addContextOptions adds TrustOptions to the AuthZEN request context.
// These are translated to go-trust server-side context parameters.
func (e *GoTrustEvaluator) addContextOptions(req *authzen.EvaluationRequest, opts *TrustOptions) {
	if opts == nil {
		return
	}

	// Initialize context if needed
	if req.Context == nil {
		req.Context = make(map[string]any)
	}

	// Map TrustOptions to go-trust context keys
	if opts.IncludeTrustChain {
		req.Context["include_trust_chain"] = true
	}
	if opts.IncludeCertificates {
		req.Context["include_certificates"] = true
	}
	if opts.BypassCache {
		req.Context["cache_control"] = "no-cache"
	}
}

// GetClient returns the underlying AuthZEN client for advanced usage.
func (e *GoTrustEvaluator) GetClient() *authzenclient.Client {
	return e.client
}

// Verify interface compliance
var (
	_ TrustEvaluator       = (*GoTrustEvaluator)(nil)
	_ KeyResolver          = (*GoTrustEvaluator)(nil)
	_ CombinedTrustService = (*GoTrustEvaluator)(nil)
)
