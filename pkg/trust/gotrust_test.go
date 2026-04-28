package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

func TestNewTrustEvaluatorFromConfig_NoPDP(t *testing.T) {
	// When no PDP URL is provided, should return AllowAllEvaluator
	eval := NewTrustEvaluatorFromConfig("")

	_, ok := eval.(*AllowAllEvaluator)
	if !ok {
		t.Errorf("expected AllowAllEvaluator when pdpURL is empty, got %T", eval)
	}
}

func TestNewTrustEvaluatorFromConfig_WithPDP(t *testing.T) {
	// When PDP URL is provided, should return GoTrustEvaluator
	eval := NewTrustEvaluatorFromConfig("https://pdp.example.com")

	_, ok := eval.(*GoTrustEvaluator)
	if !ok {
		t.Errorf("expected GoTrustEvaluator when pdpURL is set, got %T", eval)
	}
}

func TestGoTrustEvaluator_SupportsKeyType(t *testing.T) {
	eval := NewGoTrustEvaluator("https://pdp.example.com")

	tests := []struct {
		name     string
		keyType  KeyType
		expected bool
	}{
		{"supports JWK", KeyTypeJWK, true},
		{"supports X5C", KeyTypeX5C, true},
		{"rejects unknown type", KeyType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eval.SupportsKeyType(tt.keyType); got != tt.expected {
				t.Errorf("SupportsKeyType(%s) = %v, want %v", tt.keyType, got, tt.expected)
			}
		})
	}
}

func TestGoTrustEvaluator_GetClient(t *testing.T) {
	eval := NewGoTrustEvaluator("https://pdp.example.com")

	client := eval.GetClient()
	if client == nil {
		t.Error("GetClient() returned nil")
	}
}

func TestNewGoTrustEvaluatorWithClient(t *testing.T) {
	client := authzenclient.New("https://pdp.example.com")
	eval := NewGoTrustEvaluatorWithClient(client)

	if eval == nil {
		t.Fatal("NewGoTrustEvaluatorWithClient returned nil")
	}

	if eval.GetClient() != client {
		t.Error("evaluator should use the provided client")
	}
}

func TestGoTrustEvaluator_EvaluateNilRequest(t *testing.T) {
	eval := NewGoTrustEvaluator("https://pdp.example.com")

	_, err := eval.Evaluate(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
	if err.Error() != ErrMsgNilRequest {
		t.Errorf("expected error message %q, got %q", ErrMsgNilRequest, err.Error())
	}
}

func TestGoTrustEvaluator_EvaluateUnsupportedKeyType(t *testing.T) {
	eval := NewGoTrustEvaluator("https://pdp.example.com")

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyType("unsupported"),
			Key:       "some-key",
		},
	}

	_, err := eval.Evaluate(context.Background(), req)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// Mock PDP server for testing
func createMockPDPServer(t *testing.T, decision bool, trustFramework string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle evaluation endpoint (default path used by authzenclient)
		if r.URL.Path == "/evaluation" {
			resp := authzen.EvaluationResponse{
				Decision: decision,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{
						"user": "test reason",
					},
					TrustMetadata: map[string]any{
						"trust_framework": trustFramework,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
			return
		}
		http.NotFound(w, r)
	}))
}

func TestGoTrustEvaluator_EvaluateJWK(t *testing.T) {
	server := createMockPDPServer(t, true, "test-framework")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// Create test Ed25519 key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       pubKey,
			Role:      RoleIssuer,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
	if decision.TrustFramework != "test-framework" {
		t.Errorf("expected TrustFramework='test-framework', got %s", decision.TrustFramework)
	}
	if decision.Reason != "test reason" {
		t.Errorf("expected Reason='test reason', got %s", decision.Reason)
	}
}

func TestGoTrustEvaluator_EvaluateJWK_ECDSA(t *testing.T) {
	server := createMockPDPServer(t, true, "ecdsa-framework")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// Create test ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       &privateKey.PublicKey,
			Role:      RoleIssuer,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
}

func TestGoTrustEvaluator_EvaluateJWK_Map(t *testing.T) {
	server := createMockPDPServer(t, true, "jwk-framework")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "test-x-value",
	}

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       jwk,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
}

func TestGoTrustEvaluator_EvaluateX5C(t *testing.T) {
	server := createMockPDPServer(t, true, "x509")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// Create test certificate chain
	chain := createTestCertChainForGoTrust(t)

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       chain,
			Role:      RoleIssuer,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
	if decision.TrustFramework != "x509" {
		t.Errorf("expected TrustFramework='x509', got %s", decision.TrustFramework)
	}
}

func TestGoTrustEvaluator_EvaluateX5C_AsStrings(t *testing.T) {
	server := createMockPDPServer(t, true, "x509")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// X5C as base64 strings (common in SD-JWT)
	x5cStrings := []string{"base64cert1", "base64cert2"}

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       x5cStrings,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
}

func TestGoTrustEvaluator_EvaluateX5C_CertChainType(t *testing.T) {
	server := createMockPDPServer(t, true, "x509")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// Use X5CCertChain type
	chain := createTestCertChainForGoTrust(t)
	certChain := X5CCertChain(chain)

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       certChain,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
}

func TestGoTrustEvaluator_EvaluateWithOptions(t *testing.T) {
	server := createMockPDPServer(t, true, "test-framework")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       pubKey,
			Options: &TrustOptions{
				IncludeTrustChain:   true,
				IncludeCertificates: true,
				BypassCache:         true,
			},
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
}

func TestGoTrustEvaluator_EvaluateUntrusted(t *testing.T) {
	server := createMockPDPServer(t, false, "")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://untrusted-issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       pubKey,
		},
	}

	decision, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Trusted {
		t.Error("expected Trusted=false")
	}
}

func TestGoTrustEvaluator_buildJWKRequest_InvalidKey(t *testing.T) {
	eval := NewGoTrustEvaluator("https://pdp.example.com")

	// crypto.PublicKey that's not ECDSA or Ed25519 should fail
	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeJWK,
			Key:       "invalid-key-type", // String is not a valid key
		},
	}

	_, err := eval.Evaluate(context.Background(), req)
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

func TestGoTrustEvaluator_buildX5CRequest_InvalidKey(t *testing.T) {
	server := createMockPDPServer(t, true, "x509")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	req := &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       "invalid-key-type", // String is not valid for X5C
		},
	}

	_, err := eval.Evaluate(context.Background(), req)
	if err == nil {
		t.Error("expected error for invalid X5C key type")
	}
}

// Helper to create test certificate chain
func createTestCertChainForGoTrust(t *testing.T) []*x509.Certificate {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "https://issuer.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	return []*x509.Certificate{leafCert, rootCert}
}

// createMockResolutionServer creates a mock PDP that returns resolution responses with DID documents
func createMockResolutionServer(t *testing.T, decision bool, verificationMethod string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evaluation" {
			var resp authzen.EvaluationResponse
			if decision {
				// Build JWK for ECDSA P-256 with valid test coordinates
				// These are the base64url-encoded coordinates for a valid P-256 test key
				resp = authzen.EvaluationResponse{
					Decision: decision,
					Context: &authzen.EvaluationResponseContext{
						TrustMetadata: map[string]any{
							"id": "did:example:123",
							"verificationMethod": []any{
								map[string]any{
									"id":   verificationMethod,
									"type": "JsonWebKey2020",
									"publicKeyJwk": map[string]any{
										"kty": "EC",
										"crv": "P-256",
										// Valid P-256 test key (from RFC 7517 example)
										"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
										"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
									},
								},
							},
						},
					},
				}
			} else {
				resp = authzen.EvaluationResponse{
					Decision: false,
					Context: &authzen.EvaluationResponseContext{
						Reason: map[string]any{
							"error": "verification method not trusted",
						},
					},
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
			return
		}
		http.NotFound(w, r)
	}))
}

func TestGoTrustEvaluator_ResolveKey_Success(t *testing.T) {
	verificationMethod := "did:example:123#key-1"
	server := createMockResolutionServer(t, true, verificationMethod)
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	key, err := eval.ResolveKey(context.Background(), verificationMethod)
	if err != nil {
		t.Fatalf("ResolveKey failed: %v", err)
	}

	if key == nil {
		t.Error("expected non-nil key")
	}

	// Verify it's an ECDSA key
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected ECDSA public key, got %T", key)
	}
}

func TestGoTrustEvaluator_ResolveKey_Denied(t *testing.T) {
	server := createMockResolutionServer(t, false, "did:example:123#key-1")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	_, err := eval.ResolveKey(context.Background(), "did:example:123#key-1")
	if err == nil {
		t.Error("expected error for denied resolution")
	}

	// Verify error message contains the reason
	if !containsSubstring(err.Error(), "resolution denied") {
		t.Errorf("expected 'resolution denied' in error, got: %v", err)
	}
}

func TestGoTrustEvaluator_ResolveKey_MissingMetadata(t *testing.T) {
	// Create server that returns decision=true but no trust metadata
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := authzen.EvaluationResponse{
			Decision: true,
			Context:  nil, // No context
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) // #nosec G104
	}))
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	_, err := eval.ResolveKey(context.Background(), "did:example:123#key-1")
	if err == nil {
		t.Error("expected error when trust metadata is missing")
	}
}

func TestGoTrustEvaluator_ResolveKey_MethodNotFound(t *testing.T) {
	// Create server that returns valid response but with different verification method ID
	server := createMockResolutionServer(t, true, "did:example:123#key-2")
	defer server.Close()

	eval := NewGoTrustEvaluator(server.URL)

	// Request different verification method than what's in the response
	_, err := eval.ResolveKey(context.Background(), "did:example:123#key-1")
	if err == nil {
		t.Error("expected error when verification method not found")
	}
}

// Helper function for string matching uses strings.Contains for efficiency.
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
