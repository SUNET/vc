package trust

import (
	"context"
	"crypto"
	"fmt"
)

// AllowAllEvaluator is a TrustEvaluator that always returns trusted=true.
// This is used when no PDP URL is configured ("allow all" mode).
//
// In "allow all" mode:
//   - All trust evaluation requests return Trusted=true
//   - The TrustFramework is set to "none" to indicate no trust validation occurred
//   - Key resolution is not supported (returns an error)
//
// This provides a consistent behavior across applications when trust evaluation
// is not required or during development/testing scenarios.
type AllowAllEvaluator struct{}

// NewAllowAllEvaluator creates a trust evaluator that accepts all requests.
// Use this when operating in "allow all" mode without a PDP.
func NewAllowAllEvaluator() *AllowAllEvaluator {
	return &AllowAllEvaluator{}
}

// Evaluate implements TrustEvaluator. Always returns trusted=true for supported key types.
func (e *AllowAllEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if req == nil {
		return nil, fmt.Errorf("%s", ErrMsgNilRequest)
	}

	// Validate key type to maintain consistency with other evaluators
	if !e.SupportsKeyType(req.KeyType) {
		return &TrustDecision{
			Trusted: false,
			Reason:  fmt.Sprintf("unsupported key type: %s", req.KeyType),
		}, nil
	}

	return &TrustDecision{
		Trusted:        true,
		Reason:         "allow all mode: no PDP configured",
		TrustFramework: TrustFrameworkNone,
	}, nil
}

// SupportsKeyType implements TrustEvaluator. Supports JWK and X5C key types.
func (e *AllowAllEvaluator) SupportsKeyType(kt KeyType) bool {
	// Support known key types in allow-all mode
	return kt == KeyTypeJWK || kt == KeyTypeX5C
}

// ResolveKey attempts to resolve a key but is not supported in allow-all mode.
// Key resolution requires an actual PDP service to resolve DIDs and verify trust.
func (e *AllowAllEvaluator) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	// Key resolution is not supported in allow-all mode because we need
	// an actual resolver to fetch DID documents and extract keys.
	// This is a fundamental limitation - we can "allow" trust but not resolve.
	return nil, fmt.Errorf("key resolution not supported in allow-all mode (no PDP configured)")
}

// Verify interface compliance
var (
	_ TrustEvaluator = (*AllowAllEvaluator)(nil)
	_ KeyResolver    = (*AllowAllEvaluator)(nil)
)
