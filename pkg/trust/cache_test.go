package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// testReq creates an EvaluationRequest for testing
func testReq(subjectID string, keyType KeyType, role Role) *EvaluationRequest {
	return &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: subjectID,
			KeyType:   keyType,
			Role:      role,
		},
	}
}

// testReqWithKey creates an EvaluationRequest with a key for testing
func testReqWithKey(subjectID string, keyType KeyType, key any, role Role) *EvaluationRequest {
	return &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: subjectID,
			KeyType:   keyType,
			Key:       key,
			Role:      role,
		},
	}
}

// testReqWithOptions creates an EvaluationRequest with options for testing
func testReqWithOptions(subjectID string, keyType KeyType, role Role, opts *TrustOptions) *EvaluationRequest {
	return &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: subjectID,
			KeyType:   keyType,
			Role:      role,
			Options:   opts,
		},
	}
}

func TestTrustCache_BasicOperations(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{
		TTL: 1 * time.Minute,
	})
	defer cache.Stop()

	req := testReq("did:web:example.com", KeyTypeJWK, RoleIssuer)

	decision := &TrustDecision{
		Trusted:        true,
		Reason:         "Test decision",
		TrustFramework: "test",
	}

	// Initially empty
	if got := cache.Get(req); got != nil {
		t.Error("expected nil from empty cache")
	}

	// Set and get
	cache.Set(req, decision)

	got := cache.Get(req)
	if got == nil {
		t.Fatal("expected cached decision")
	}
	if !got.Trusted {
		t.Error("expected Trusted=true")
	}
	if got.Reason != "Test decision" {
		t.Errorf("expected reason 'Test decision', got %s", got.Reason)
	}

	// Invalidate
	cache.Invalidate(req)
	if got := cache.Get(req); got != nil {
		t.Error("expected nil after invalidation")
	}
}

func TestTrustCache_DifferentRequests(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{})
	defer cache.Stop()

	req1 := testReq("did:web:issuer1.com", KeyTypeJWK, RoleIssuer)
	req2 := testReq("did:web:issuer2.com", KeyTypeJWK, RoleIssuer)

	decision1 := &TrustDecision{Trusted: true, Reason: "issuer1"}
	decision2 := &TrustDecision{Trusted: false, Reason: "issuer2"}

	cache.Set(req1, decision1)
	cache.Set(req2, decision2)

	got1 := cache.Get(req1)
	got2 := cache.Get(req2)

	if got1 == nil || got1.Reason != "issuer1" {
		t.Error("req1 cache miss or wrong value")
	}
	if got2 == nil || got2.Reason != "issuer2" {
		t.Error("req2 cache miss or wrong value")
	}
}

func TestTrustCache_KeyTypeDistinction(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{})
	defer cache.Stop()

	reqJWK := testReq("https://issuer.example.com", KeyTypeJWK, RoleIssuer)
	reqX5C := testReq("https://issuer.example.com", KeyTypeX5C, RoleIssuer)

	decisionJWK := &TrustDecision{Trusted: true, Reason: "jwk"}
	decisionX5C := &TrustDecision{Trusted: true, Reason: "x5c"}

	cache.Set(reqJWK, decisionJWK)
	cache.Set(reqX5C, decisionX5C)

	if got := cache.Get(reqJWK); got == nil || got.Reason != "jwk" {
		t.Error("JWK cache entry wrong")
	}
	if got := cache.Get(reqX5C); got == nil || got.Reason != "x5c" {
		t.Error("X5C cache entry wrong")
	}
}

func TestTrustCache_RoleDistinction(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{})
	defer cache.Stop()

	reqIssuer := testReq("did:web:example.com", KeyTypeJWK, RoleIssuer)
	reqVerifier := testReq("did:web:example.com", KeyTypeJWK, RoleVerifier)

	decisionIssuer := &TrustDecision{Trusted: true, Reason: "issuer"}
	decisionVerifier := &TrustDecision{Trusted: false, Reason: "verifier"}

	cache.Set(reqIssuer, decisionIssuer)
	cache.Set(reqVerifier, decisionVerifier)

	if got := cache.Get(reqIssuer); got == nil || got.Reason != "issuer" {
		t.Error("issuer cache entry wrong")
	}
	if got := cache.Get(reqVerifier); got == nil || got.Reason != "verifier" {
		t.Error("verifier cache entry wrong")
	}
}

func TestTrustCache_KeyFingerprintX5C(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{})
	defer cache.Stop()

	// Create two different certificates
	cert1 := createTestCert(t, "CN=Test1")
	cert2 := createTestCert(t, "CN=Test2")

	req1 := testReqWithKey("https://issuer.example.com", KeyTypeX5C, []*x509.Certificate{cert1}, RoleIssuer)
	req2 := testReqWithKey("https://issuer.example.com", KeyTypeX5C, []*x509.Certificate{cert2}, RoleIssuer)

	decision1 := &TrustDecision{Trusted: true, Reason: "cert1"}
	decision2 := &TrustDecision{Trusted: true, Reason: "cert2"}

	cache.Set(req1, decision1)
	cache.Set(req2, decision2)

	// Different certs should have different cache entries
	if got := cache.Get(req1); got == nil || got.Reason != "cert1" {
		t.Error("cert1 cache entry wrong")
	}
	if got := cache.Get(req2); got == nil || got.Reason != "cert2" {
		t.Error("cert2 cache entry wrong")
	}

	if cache.Len() != 2 {
		t.Errorf("expected 2 cache entries, got %d", cache.Len())
	}
}

func TestTrustCache_Clear(t *testing.T) {
	cache := NewTrustCache(TrustCacheConfig{})
	defer cache.Stop()

	for i := range 5 {
		req := testReq("did:web:example.com", KeyTypeJWK, Role("role-"+string(rune('a'+i))))
		cache.Set(req, &TrustDecision{Trusted: true})
	}

	if cache.Len() != 5 {
		t.Errorf("expected 5 entries, got %d", cache.Len())
	}

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("expected 0 entries after clear, got %d", cache.Len())
	}
}

func TestCachingTrustEvaluator(t *testing.T) {
	// Create a mock evaluator that counts calls
	callCount := 0
	mockEvaluator := &mockTrustEvaluator{
		evaluateFunc: func(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
			callCount++
			return &TrustDecision{
				Trusted: true,
				Reason:  "mock",
			}, nil
		},
	}

	caching := NewCachingTrustEvaluator(mockEvaluator, TrustCacheConfig{
		TTL: 1 * time.Minute,
	})
	defer caching.Stop()

	req := testReq("did:web:example.com", KeyTypeJWK, RoleIssuer)

	// First call should hit the evaluator
	_, err := caching.Evaluate(t.Context(), req)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call should hit cache
	_, err = caching.Evaluate(t.Context(), req)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call (cached), got %d", callCount)
	}
}

func TestCachingTrustEvaluator_BypassCache(t *testing.T) {
	callCount := 0
	mockEvaluator := &mockTrustEvaluator{
		evaluateFunc: func(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
			callCount++
			return &TrustDecision{Trusted: true}, nil
		},
	}

	caching := NewCachingTrustEvaluator(mockEvaluator, TrustCacheConfig{})
	defer caching.Stop()

	req := testReqWithOptions("did:web:example.com", KeyTypeJWK, RoleIssuer, &TrustOptions{BypassCache: true})

	// Both calls should hit the evaluator (bypass cache)
	caching.Evaluate(t.Context(), req)
	caching.Evaluate(t.Context(), req)

	if callCount != 2 {
		t.Errorf("expected 2 calls with bypass, got %d", callCount)
	}
}

func TestCachingTrustEvaluator_NegativeNotCached(t *testing.T) {
	callCount := 0
	mockEvaluator := &mockTrustEvaluator{
		evaluateFunc: func(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
			callCount++
			return &TrustDecision{Trusted: false, Reason: "untrusted"}, nil
		},
	}

	caching := NewCachingTrustEvaluator(mockEvaluator, TrustCacheConfig{})
	defer caching.Stop()

	req := testReq("did:web:untrusted.com", KeyTypeJWK, RoleIssuer)

	// Negative decisions are not cached by default
	caching.Evaluate(t.Context(), req)
	caching.Evaluate(t.Context(), req)

	if callCount != 2 {
		t.Errorf("expected 2 calls (negative not cached), got %d", callCount)
	}
}

// mockTrustEvaluator is a test helper
type mockTrustEvaluator struct {
	evaluateFunc func(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)
}

func (m *mockTrustEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, req)
	}
	return &TrustDecision{Trusted: true}, nil
}

func (m *mockTrustEvaluator) SupportsKeyType(kt KeyType) bool {
	return true
}

// createTestCert creates a self-signed certificate for testing
func createTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestComputeKeyFingerprint(t *testing.T) {
	// Test X5C fingerprint
	cert := createTestCert(t, "CN=Test")
	chain := []*x509.Certificate{cert}

	fp1 := computeKeyFingerprint(chain, KeyTypeX5C)
	fp2 := computeKeyFingerprint(chain, KeyTypeX5C)

	if fp1 == "" {
		t.Error("expected non-empty fingerprint")
	}
	if fp1 != fp2 {
		t.Error("fingerprint should be deterministic")
	}

	// Different cert should have different fingerprint
	cert2 := createTestCert(t, "CN=Test2")
	chain2 := []*x509.Certificate{cert2}
	fp3 := computeKeyFingerprint(chain2, KeyTypeX5C)

	if fp1 == fp3 {
		t.Error("different certs should have different fingerprints")
	}
}

func TestComputeKeyFingerprint_JWK(t *testing.T) {
	jwk1 := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}
	jwk2 := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "different-y",
	}

	fp1 := computeKeyFingerprint(jwk1, KeyTypeJWK)
	fp2 := computeKeyFingerprint(jwk2, KeyTypeJWK)

	if fp1 == "" {
		t.Error("expected non-empty fingerprint")
	}
	if fp1 == fp2 {
		t.Error("different JWKs should have different fingerprints")
	}
}
