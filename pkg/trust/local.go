package trust

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
	"time"
)

// LocalTrustEvaluator implements TrustEvaluator using local trust anchors.
//
// Deprecated: LocalTrustEvaluator performs trust evaluation locally without
// consulting an AuthZEN PDP. For harmonized trust management across applications,
// use NewTrustEvaluatorFromConfig instead, which returns AllowAllEvaluator when
// no PDP URL is configured (returning trusted=true for all requests).
//
// LocalTrustEvaluator is retained for backward compatibility and testing purposes.
type LocalTrustEvaluator struct {
	mu              sync.RWMutex
	trustedRoots    []*x509.Certificate
	trustedRootPool *x509.CertPool
	allowedRoles    map[string]bool // nil means all roles allowed
	clock           func() time.Time
}

// LocalTrustConfig configures a LocalTrustEvaluator.
//
// Deprecated: See LocalTrustEvaluator deprecation notice.
type LocalTrustConfig struct {
	// TrustedRoots are the trusted root certificates.
	TrustedRoots []*x509.Certificate

	// AllowedRoles limits which roles are accepted. Nil means all roles.
	AllowedRoles []string

	// Clock is used for time-based validation. If nil, time.Now() is used.
	Clock func() time.Time
}

// NewLocalTrustEvaluator creates a new local trust evaluator.
func NewLocalTrustEvaluator(config LocalTrustConfig) *LocalTrustEvaluator {
	pool := x509.NewCertPool()
	for _, cert := range config.TrustedRoots {
		pool.AddCert(cert)
	}

	var allowedRoles map[string]bool
	if len(config.AllowedRoles) > 0 {
		allowedRoles = make(map[string]bool)
		for _, role := range config.AllowedRoles {
			allowedRoles[role] = true
		}
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	return &LocalTrustEvaluator{
		trustedRoots:    config.TrustedRoots,
		trustedRootPool: pool,
		allowedRoles:    allowedRoles,
		clock:           clock,
	}
}

// AddTrustedRoot adds a trusted root certificate.
func (e *LocalTrustEvaluator) AddTrustedRoot(cert *x509.Certificate) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.trustedRoots = append(e.trustedRoots, cert)
	e.trustedRootPool.AddCert(cert)
}

// Evaluate implements TrustEvaluator.
func (e *LocalTrustEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if req == nil {
		return nil, fmt.Errorf("%s", ErrMsgNilRequest)
	}

	// Check role if restricted
	if e.allowedRoles != nil && req.Role != "" && !e.allowedRoles[string(req.Role)] {
		return &TrustDecision{
			Trusted: false,
			Reason:  fmt.Sprintf("role '%s' not in allowed roles", req.Role),
		}, nil
	}

	switch req.KeyType {
	case KeyTypeX5C:
		return e.evaluateX5C(ctx, req)
	case KeyTypeJWK:
		// JWK validation not supported for local trust (needs external verification)
		return &TrustDecision{
			Trusted: false,
			Reason:  "local trust evaluator does not support JWK validation",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}
}

// evaluateX5C validates an x5c certificate chain against local trust roots.
func (e *LocalTrustEvaluator) evaluateX5C(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var chain []*x509.Certificate

	switch k := req.Key.(type) {
	case []*x509.Certificate:
		chain = k
	case X5CCertChain:
		chain = []*x509.Certificate(k)
	default:
		return nil, fmt.Errorf("invalid key type for x5c: %T", req.Key)
	}

	if len(chain) == 0 {
		return &TrustDecision{
			Trusted: false,
			Reason:  "empty certificate chain",
		}, nil
	}

	leaf := chain[0]
	now := e.clock()

	// Check certificate validity period
	if now.Before(leaf.NotBefore) {
		return &TrustDecision{
			Trusted: false,
			Reason:  fmt.Sprintf("certificate not yet valid: valid from %s", leaf.NotBefore),
		}, nil
	}
	if now.After(leaf.NotAfter) {
		return &TrustDecision{
			Trusted: false,
			Reason:  fmt.Sprintf("certificate expired: valid until %s", leaf.NotAfter),
		}, nil
	}

	// Build verification options
	opts := x509.VerifyOptions{
		Roots:       e.trustedRootPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Add intermediates if present
	if len(chain) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	// Verify the chain
	if _, err := leaf.Verify(opts); err != nil {
		return &TrustDecision{
			Trusted: false,
			Reason:  fmt.Sprintf("certificate chain verification failed: %v", err),
		}, nil
	}

	// Verify subject ID matches certificate (if specified)
	if req.SubjectID != "" {
		if !certificateMatchesSubject(leaf, req.SubjectID) {
			return &TrustDecision{
				Trusted: false,
				Reason:  fmt.Sprintf("certificate subject does not match expected subject ID: %s", req.SubjectID),
			}, nil
		}
	}

	return &TrustDecision{
		Trusted:        true,
		Reason:         "certificate chain verified against local trust anchors",
		TrustFramework: "local",
	}, nil
}

// SupportsKeyType implements TrustEvaluator.
func (e *LocalTrustEvaluator) SupportsKeyType(kt KeyType) bool {
	return kt == KeyTypeX5C
}

// certificateMatchesSubject checks if a certificate matches the expected subject ID.
func certificateMatchesSubject(cert *x509.Certificate, subjectID string) bool {
	// Check Subject CN
	if cert.Subject.CommonName == subjectID {
		return true
	}

	// Check SAN URIs
	for _, uri := range cert.URIs {
		if uri.String() == subjectID {
			return true
		}
	}

	// Check SAN DNS names
	if slices.Contains(cert.DNSNames, subjectID) {
		return true
	}

	// Check SAN email addresses
	return slices.Contains(cert.EmailAddresses, subjectID)
}

// GetTrustedRoots returns all trusted root certificates.
func (e *LocalTrustEvaluator) GetTrustedRoots() []*x509.Certificate {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*x509.Certificate, len(e.trustedRoots))
	copy(result, e.trustedRoots)
	return result
}

// Verify interface compliance
var _ TrustEvaluator = (*LocalTrustEvaluator)(nil)
