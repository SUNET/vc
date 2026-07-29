package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// =============================================================================
// GoTrustResolver Tests using testserver
// =============================================================================

func TestGoTrustResolver_WithTestServer_AcceptAll(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test that we can create a resolver against the test server
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	if resolver.GetClient() == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestGoTrustResolver_WithTestServer_Discovery(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// Test discovery workflow - creates resolver by fetching .well-known/authzen-configuration
	resolver, err := NewGoTrustResolverWithDiscovery(t.Context(), srv.URL())
	if err != nil {
		t.Fatalf("failed to create resolver with discovery: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}

	// Verify we can get metadata from the client
	client := resolver.GetClient()
	if client.Metadata == nil {
		t.Fatal("expected non-nil metadata after discovery")
	}
	if client.Metadata.PolicyDecisionPoint == "" {
		t.Fatal("expected non-empty PDP URL in metadata")
	}
}

func TestGoTrustResolver_WithTestServer_EvaluateTrustEd25519_Accepted(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resolver := NewGoTrustResolver(srv.URL())
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision from accept-all server")
	}
}

func TestGoTrustResolver_WithTestServer_EvaluateTrustEd25519_Rejected(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resolver := NewGoTrustResolver(srv.URL())
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:untrusted.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Fatal("expected rejected decision from reject-all server")
	}
}

func TestGoTrustResolver_WithTestServer_EvaluateTrustECDSA_Accepted(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resolver := NewGoTrustResolver(srv.URL())
	trusted, err := resolver.EvaluateTrustECDSA(t.Context(), "did:web:example.com", &privKey.PublicKey, "verifier")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision from accept-all server")
	}
}

func TestGoTrustResolver_WithTestServer_EvaluateTrustECDSA_Rejected(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resolver := NewGoTrustResolver(srv.URL())
	trusted, err := resolver.EvaluateTrustECDSA(t.Context(), "did:web:untrusted.com", &privKey.PublicKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Fatal("expected rejected decision from reject-all server")
	}
}

// =============================================================================
// Dynamic Decision Tests - Test complex trust logic
// =============================================================================

func TestGoTrustResolver_WithTestServer_DynamicDecision_BySubjectID(t *testing.T) {
	// Server that accepts only specific DIDs
	trustedDIDs := map[string]bool{
		"did:web:trusted-issuer.example.com": true,
		"did:web:trusted-verifier.io":        true,
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		if trustedDIDs[req.Subject.ID] {
			return &authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{
						"message": "Subject is in trusted list",
					},
				},
			}, nil
		}
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error": "Subject not in trusted list",
				},
			},
		}, nil
	}))
	defer srv.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	resolver := NewGoTrustResolver(srv.URL())

	// Test trusted DID
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:trusted-issuer.example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Error("expected trusted-issuer.example.com to be trusted")
	}

	// Test untrusted DID
	trusted, err = resolver.EvaluateTrustEd25519(t.Context(), "did:web:unknown.org", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Error("expected unknown.org to be untrusted")
	}
}

func TestGoTrustResolver_WithTestServer_DynamicDecision_ByRole(t *testing.T) {
	// Server that accepts based on role
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		allowedRoles := []string{"issuer", "verifier", "wallet-provider"}

		if req.Action == nil {
			// No role specified - allow
			return &authzen.EvaluationResponse{Decision: true}, nil
		}

		if slices.Contains(allowedRoles, req.Action.Name) {
			return &authzen.EvaluationResponse{Decision: true}, nil
		}

		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error": "Role not allowed: " + req.Action.Name,
				},
			},
		}, nil
	}))
	defer srv.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	resolver := NewGoTrustResolver(srv.URL())

	// Test allowed role
	trusted, _ := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "issuer")
	if !trusted {
		t.Error("expected 'issuer' role to be trusted")
	}

	// Test another allowed role
	trusted, _ = resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "verifier")
	if !trusted {
		t.Error("expected 'verifier' role to be trusted")
	}

	// Test disallowed role
	trusted, _ = resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "attacker")
	if trusted {
		t.Error("expected 'attacker' role to be rejected")
	}

	// Test no role (should be allowed)
	trusted, _ = resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "")
	if !trusted {
		t.Error("expected empty role to be trusted")
	}
}

// =============================================================================
// GoTrustEvaluator Tests using testserver
// =============================================================================

func TestGoTrustEvaluator_WithTestServer_AcceptAll(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	evaluator := NewGoTrustEvaluator(srv.URL())
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	trusted, err := evaluator.EvaluateTrust("did:web:example.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestGoTrustEvaluator_WithTestServer_RejectAll(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	evaluator := NewGoTrustEvaluator(srv.URL())
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	trusted, err := evaluator.EvaluateTrust("did:web:example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Fatal("expected rejected decision")
	}
}

func TestGoTrustEvaluator_WithTestServer_ECDSA(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	evaluator := NewGoTrustEvaluator(srv.URL())
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	trusted, err := evaluator.EvaluateTrustECDSA("did:web:example.com", &privKey.PublicKey, "verifier")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestGoTrustEvaluator_WithTestServer_Discovery(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	evaluator, err := NewGoTrustEvaluatorWithDiscovery(t.Context(), srv.URL())
	if err != nil {
		t.Fatalf("failed to create evaluator with discovery: %v", err)
	}

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	trusted, err := evaluator.EvaluateTrust("did:web:example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

// =============================================================================
// ValidatingResolver Tests using testserver
// =============================================================================

func TestValidatingResolver_WithTestServer_TrustedKey(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create a static resolver with the key
	staticResolver := NewStaticResolver()
	staticResolver.AddKey("did:web:example.com#key-1", pubKey)

	// Create a trust evaluator using the test server
	evaluator := NewGoTrustEvaluator(srv.URL())

	// Create validating resolver
	validatingResolver := NewValidatingResolver(staticResolver, evaluator, "issuer")

	resolvedKey, err := validatingResolver.ResolveEd25519("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestValidatingResolver_WithTestServer_UntrustedKey(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	staticResolver := NewStaticResolver()
	staticResolver.AddKey("did:web:untrusted.com#key-1", pubKey)

	evaluator := NewGoTrustEvaluator(srv.URL())
	validatingResolver := NewValidatingResolver(staticResolver, evaluator, "")

	_, err := validatingResolver.ResolveEd25519("did:web:untrusted.com#key-1")
	if err == nil {
		t.Fatal("expected error for untrusted key")
	}
	if err.Error() != "key not trusted for did:web:untrusted.com#key-1" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidatingResolver_WithTestServer_DynamicTrust(t *testing.T) {
	// Server that only trusts specific DIDs
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		if req.Subject.ID == "did:web:trusted.example.com" {
			return &authzen.EvaluationResponse{Decision: true}, nil
		}
		return &authzen.EvaluationResponse{Decision: false}, nil
	}))
	defer srv.Close()

	trustedKey, _, _ := ed25519.GenerateKey(rand.Reader)
	untrustedKey, _, _ := ed25519.GenerateKey(rand.Reader)

	staticResolver := NewStaticResolver()
	staticResolver.AddKey("did:web:trusted.example.com#key-1", trustedKey)
	staticResolver.AddKey("did:web:untrusted.example.com#key-1", untrustedKey)

	evaluator := NewGoTrustEvaluator(srv.URL())
	validatingResolver := NewValidatingResolver(staticResolver, evaluator, "")

	// Trusted DID should work
	key, err := validatingResolver.ResolveEd25519("did:web:trusted.example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve trusted key: %v", err)
	}
	if !trustedKey.Equal(key) {
		t.Fatal("resolved key doesn't match")
	}

	// Untrusted DID should fail
	_, err = validatingResolver.ResolveEd25519("did:web:untrusted.example.com#key-1")
	if err == nil {
		t.Fatal("expected error for untrusted key")
	}
}

// =============================================================================
// Resolution Tests with Mock DID Documents
// =============================================================================

func TestGoTrustResolver_WithTestServer_Resolution_Ed25519(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create a mock DID document
	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "did:web:example.com#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}

	// Server that returns the DID document as trust_metadata
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	resolvedKey, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}

	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestGoTrustResolver_WithTestServer_Resolution_ECDSA(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey

	jwk, _ := ECDSAToJWK(pubKey)

	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "did:web:example.com#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": jwk,
			},
		},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	resolvedKey, err := resolver.ResolveECDSA("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}

	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestGoTrustResolver_WithTestServer_Resolution_Denied(t *testing.T) {
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error": "DID not found in registry",
				},
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	_, err := resolver.ResolveEd25519("did:web:unknown.com#key-1")
	if err == nil {
		t.Fatal("expected error for denied resolution")
	}
	if !stringContains(err.Error(), "resolution denied") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGoTrustResolver_WithTestServer_Resolution_NoMetadata(t *testing.T) {
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			// No Context or TrustMetadata
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	_, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error when no metadata returned")
	}
	if !stringContains(err.Error(), "no trust_metadata") {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// Integration Tests - Full workflow scenarios
// =============================================================================

func TestIntegration_IssuerCredentialFlow(t *testing.T) {
	// Simulate a credential issuance flow:
	// 1. Issuer presents a credential with their DID
	// 2. Verifier resolves issuer's key
	// 3. Verifier validates trust in issuer
	// 4. Verifier verifies signature

	issuerKey, _, _ := ed25519.GenerateKey(rand.Reader)
	issuerDID := "did:web:issuer.example.com"
	issuerVM := issuerDID + "#key-1"

	issuerDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       issuerDID,
		"verificationMethod": []any{
			map[string]any{
				"id":           issuerVM,
				"type":         "JsonWebKey2020",
				"controller":   issuerDID,
				"publicKeyJwk": Ed25519ToJWK(issuerKey),
			},
		},
		"assertionMethod": []any{issuerVM},
	}

	// Trust server that:
	// - Returns DID document for resolution
	// - Only trusts issuers with "issuer" role
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		// Resolution request (no resource.key)
		if req.Resource.Type == "" || len(req.Resource.Key) == 0 {
			if req.Subject.ID == issuerDID || req.Subject.ID == issuerVM {
				return &authzen.EvaluationResponse{
					Decision: true,
					Context: &authzen.EvaluationResponseContext{
						TrustMetadata: issuerDoc,
					},
				}, nil
			}
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{"error": "unknown DID"},
				},
			}, nil
		}

		// Full trust evaluation
		if req.Subject.ID == issuerDID && req.Action != nil && req.Action.Name == "issuer" {
			return &authzen.EvaluationResponse{Decision: true}, nil
		}
		return &authzen.EvaluationResponse{Decision: false}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Step 1: Resolve issuer's key
	resolvedKey, err := resolver.ResolveEd25519(issuerVM)
	if err != nil {
		t.Fatalf("failed to resolve issuer key: %v", err)
	}
	if !issuerKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match issuer key")
	}

	// Step 2: Validate trust in issuer
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), issuerDID, issuerKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected issuer to be trusted")
	}

	// Step 3: Verify untrusted role is rejected
	trusted, err = resolver.EvaluateTrustEd25519(t.Context(), issuerDID, issuerKey, "admin")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Fatal("expected 'admin' role to be rejected")
	}
}

func TestIntegration_MultipleKeyTypes(t *testing.T) {
	// Test a DID document with both Ed25519 and ECDSA keys
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	ecdsaPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey := &ecdsaPrivKey.PublicKey

	ecdsaJWK, _ := ECDSAToJWK(ecdsaKey)

	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "did:web:example.com#key-ed25519",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": Ed25519ToJWK(ed25519Key),
			},
			map[string]any{
				"id":           "did:web:example.com#key-ecdsa",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": ecdsaJWK,
			},
		},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Resolve Ed25519 key
	resolvedEd25519, err := resolver.ResolveEd25519("did:web:example.com#key-ed25519")
	if err != nil {
		t.Fatalf("failed to resolve Ed25519 key: %v", err)
	}
	if !ed25519Key.Equal(resolvedEd25519) {
		t.Fatal("Ed25519 key mismatch")
	}

	// Resolve ECDSA key
	resolvedECDSA, err := resolver.ResolveECDSA("did:web:example.com#key-ecdsa")
	if err != nil {
		t.Fatalf("failed to resolve ECDSA key: %v", err)
	}
	if !ecdsaKey.Equal(resolvedECDSA) {
		t.Fatal("ECDSA key mismatch")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestGoTrustResolver_WithTestServer_ServerError(t *testing.T) {
	// When the decision func returns an error, the testserver returns an HTTP 500
	// The client should handle this as an error
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return nil, errors.New("internal server error")
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "")
	// The server error should either return an error OR return false (not trusted)
	// Either behavior is acceptable for error handling
	if err == nil && trusted {
		t.Fatal("expected either an error or false trust decision when server has internal error")
	}
}

func TestGoTrustResolver_WithTestServer_InvalidServerURL(t *testing.T) {
	resolver := NewGoTrustResolver("http://localhost:99999") // Invalid port
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	_, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "")
	if err == nil {
		t.Fatal("expected error for invalid server URL")
	}
}

func TestGoTrustResolver_WithTestServer_KeyNotFound(t *testing.T) {
	// Server that returns a DID doc without the requested key
	didDoc := map[string]any{
		"@context":           []string{"https://www.w3.org/ns/did/v1"},
		"id":                 "did:web:example.com",
		"verificationMethod": []any{
			// No keys defined
		},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	_, err := resolver.ResolveEd25519("did:web:example.com#nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

// =============================================================================
// NewGoTrustResolverWithClient Tests
// =============================================================================

func TestNewGoTrustResolverWithClient_FromTestServer(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// Create client via discovery
	client, err := authzenclient.Discover(t.Context(), srv.URL())
	if err != nil {
		t.Fatalf("failed to discover: %v", err)
	}

	// Create resolver with the discovered client
	resolver := NewGoTrustResolverWithClient(client)

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

// =============================================================================
// Helper functions
// =============================================================================

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

func TestGoTrustEvaluator_WithTestServer_WithClient(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// Create client manually
	client, err := authzenclient.Discover(t.Context(), srv.URL())
	if err != nil {
		t.Fatalf("failed to discover: %v", err)
	}

	// Use NewGoTrustEvaluatorWithClient
	evaluator := NewGoTrustEvaluatorWithClient(client)
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	trusted, err := evaluator.EvaluateTrust("did:web:example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestValidatingResolver_WithTestServer_ECDSA(t *testing.T) {
	// Test ValidatingResolver.ResolveECDSA with a resolver that supports ECDSA
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey

	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// Create a mock resolver that supports both Ed25519 and ECDSA
	mockResolver := newMockECDSAResolver()
	mockResolver.ecdsaKeys["did:web:example.com#key-1"] = pubKey

	// Create a trust evaluator using the test server
	evaluator := NewGoTrustEvaluator(srv.URL())

	// Create validating resolver with the mock that implements ECDSAResolver
	validatingResolver := NewValidatingResolver(mockResolver, evaluator, "verifier")

	// This should work because mockECDSAResolver implements ECDSAResolver
	resolvedKey, err := validatingResolver.ResolveECDSA("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve ECDSA key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved ECDSA key doesn't match original")
	}
}

// mockECDSAResolver is a simple mock for ECDSA key resolution
type mockECDSAResolver struct {
	ed25519Keys map[string]ed25519.PublicKey
	ecdsaKeys   map[string]*ecdsa.PublicKey
}

func newMockECDSAResolver() *mockECDSAResolver {
	return &mockECDSAResolver{
		ed25519Keys: make(map[string]ed25519.PublicKey),
		ecdsaKeys:   make(map[string]*ecdsa.PublicKey),
	}
}

func (m *mockECDSAResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	key, ok := m.ed25519Keys[verificationMethod]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockECDSAResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	key, ok := m.ecdsaKeys[verificationMethod]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func TestValidatingResolver_WithTestServer_ECDSA_Untrusted(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey

	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	mockResolver := newMockECDSAResolver()
	mockResolver.ecdsaKeys["did:web:untrusted.com#key-1"] = pubKey

	evaluator := NewGoTrustEvaluator(srv.URL())
	validatingResolver := NewValidatingResolver(mockResolver, evaluator, "")

	_, err := validatingResolver.ResolveECDSA("did:web:untrusted.com#key-1")
	if err == nil {
		t.Fatal("expected error for untrusted ECDSA key")
	}
}

func TestValidatingResolver_WithTestServer_ECDSANotSupported(t *testing.T) {
	// Test that ValidatingResolver returns an error when there's no ECDSA key
	// registered for the requested verification method
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// StaticResolver has an Ed25519 key but no ECDSA key for this verification method
	staticResolver := NewStaticResolver()
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	staticResolver.AddKey("did:web:example.com#key-1", pubKey)

	evaluator := NewGoTrustEvaluator(srv.URL())
	validatingResolver := NewValidatingResolver(staticResolver, evaluator, "")

	_, err := validatingResolver.ResolveECDSA("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error when no ECDSA key is registered")
	}
	// StaticResolver returns "ECDSA key not found" when the key doesn't exist
	if !stringContains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGoTrustEvaluator_WithTestServer_ContextMethods(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	evaluator := NewGoTrustEvaluator(srv.URL())

	// Test Ed25519 with context
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	ctx := t.Context()
	trusted, err := evaluator.EvaluateTrustWithContext(ctx, "did:web:example.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust with context: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}

	// Test ECDSA with context
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	trusted, err = evaluator.EvaluateTrustECDSAWithContext(ctx, "did:web:example.com", &privKey.PublicKey, "verifier")
	if err != nil {
		t.Fatalf("failed to evaluate ECDSA trust with context: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision for ECDSA")
	}
}

func TestGoTrustResolver_WithTestServer_Resolution_ECDSAError(t *testing.T) {
	// Server that returns metadata without the requested key
	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":         "did:web:example.com#other-key",
				"type":       "JsonWebKey2020",
				"controller": "did:web:example.com",
				"publicKeyJwk": map[string]any{
					"kty": "EC",
					"crv": "P-256",
					"x":   "test",
					"y":   "test",
				},
			},
		},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	_, err := resolver.ResolveECDSA("did:web:example.com#nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing ECDSA key")
	}
}

func TestGoTrustResolver_WithTestServer_Resolution_InvalidJWK(t *testing.T) {
	// Server that returns a DID doc with invalid JWK
	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":         "did:web:example.com#key-1",
				"type":       "JsonWebKey2020",
				"controller": "did:web:example.com",
				"publicKeyJwk": map[string]any{
					"kty": "OKP",
					"crv": "Ed25519",
					// Missing "x" field - invalid JWK
				},
			},
		},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	_, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error for invalid JWK")
	}
}

func TestJWKConversion_ErrorCases(t *testing.T) {
	// Test JWKToEd25519 with invalid input
	invalidJWK := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "invalid-base64!!!",
	}
	_, err := JWKToEd25519(invalidJWK)
	if err == nil {
		t.Error("expected error for invalid base64 in Ed25519 JWK")
	}

	// Test JWKToECDSA with invalid input
	invalidECJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "invalid-base64!!!",
		"y":   "invalid-base64!!!",
	}
	_, err = JWKToECDSA(invalidECJWK)
	if err == nil {
		t.Error("expected error for invalid base64 in ECDSA JWK")
	}

	// Test JWKToECDSA with missing fields
	incompleteECJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test",
		// Missing "y"
	}
	_, err = JWKToECDSA(incompleteECJWK)
	if err == nil {
		t.Error("expected error for missing y field in ECDSA JWK")
	}

	// Test JWKToECDSA with unknown curve
	unknownCurveJWK := map[string]any{
		"kty": "EC",
		"crv": "P-999",
		"x":   "test",
		"y":   "test",
	}
	_, err = JWKToECDSA(unknownCurveJWK)
	if err == nil {
		t.Error("expected error for unknown curve in ECDSA JWK")
	}
}

func TestGoTrustResolver_WithTestServer_MultipleVerificationMethods(t *testing.T) {
	// Test resolving from a DID document with multiple verification methods
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	ecdsaPrivKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaKey := &ecdsaPrivKey.PublicKey

	ecdsaJWK, _ := ECDSAToJWK(ecdsaKey)

	didDoc := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []any{
			map[string]any{
				"id":           "did:web:example.com#key-auth",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": Ed25519ToJWK(ed25519Key),
			},
			map[string]any{
				"id":           "did:web:example.com#key-signing",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": ecdsaJWK,
			},
		},
		"authentication":  []any{"did:web:example.com#key-auth"},
		"assertionMethod": []any{"did:web:example.com#key-signing"},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Resolve the Ed25519 authentication key
	resolvedEd25519, err := resolver.ResolveEd25519("did:web:example.com#key-auth")
	if err != nil {
		t.Fatalf("failed to resolve Ed25519 key: %v", err)
	}
	if !ed25519Key.Equal(resolvedEd25519) {
		t.Error("Ed25519 key mismatch")
	}

	// Resolve the ECDSA signing key
	resolvedECDSA, err := resolver.ResolveECDSA("did:web:example.com#key-signing")
	if err != nil {
		t.Fatalf("failed to resolve ECDSA key: %v", err)
	}
	if !ecdsaKey.Equal(resolvedECDSA) {
		t.Error("ECDSA key mismatch")
	}
}

func TestECDSAToJWK_DifferentCurves(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	expectedCrvs := []string{"P-256", "P-384", "P-521"}

	for i, curve := range curves {
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key for %s: %v", expectedCrvs[i], err)
		}

		jwk, err := ECDSAToJWK(&privKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to convert %s key to JWK: %v", expectedCrvs[i], err)
		}

		if jwk["crv"] != expectedCrvs[i] {
			t.Errorf("expected crv=%s, got %s", expectedCrvs[i], jwk["crv"])
		}

		// Round-trip test
		roundTripped, err := JWKToECDSA(jwk)
		if err != nil {
			t.Fatalf("failed to convert %s JWK back to key: %v", expectedCrvs[i], err)
		}

		if !privKey.PublicKey.Equal(roundTripped) {
			t.Errorf("%s key round-trip mismatch", expectedCrvs[i])
		}
	}
}

// =============================================================================
// DID Method Testing Framework
// =============================================================================
//
// This section provides a generalizable framework for testing DID resolution
// across multiple DID methods. The framework is designed to:
//
// 1. Support mock DID resolution via testserver (current implementation)
// 2. Support actual did:web resolution with embedded HTTP server (future)
// 3. Enable integration with external test vectors (e.g., Singapore test vectors)
//
// The framework uses a DIDTestCase structure that can represent test vectors
// from any source, making it easy to integrate standardized test suites.

// DIDTestCase represents a test case for DID resolution.
// This structure is designed to be compatible with external test vector formats.
type DIDTestCase struct {
	Name        string           // Test case name/description
	DID         string           // The DID to resolve (e.g., "did:web:example.com")
	Method      string           // DID method (e.g., "web", "key")
	DIDDocument map[string]any   // Expected DID document structure
	Keys        []DIDKeyTestCase // Keys to test resolution for
	ExpectError bool             // Whether resolution should fail
	ErrorMatch  string           // Expected error substring (if ExpectError)
}

// DIDKeyTestCase represents a key within a DID document for testing.
type DIDKeyTestCase struct {
	KeyID        string         // Verification method ID (e.g., "did:web:example.com#key-1")
	KeyType      string         // "Ed25519" or "ECDSA"
	Curve        string         // For ECDSA: "P-256", "P-384", "P-521"
	PublicKeyJwk map[string]any // JWK representation (for verification)
	ExpectTrust  bool           // Whether trust evaluation should succeed
	Role         string         // Role for trust evaluation
}

// createMockDIDDocument generates a DID document for testing.
// This helper creates valid DID documents that match the W3C DID Core spec.
func createMockDIDDocument(did string, keys []DIDKeyTestCase) map[string]any {
	verificationMethods := make([]any, 0, len(keys))
	authenticationRefs := make([]any, 0)
	assertionMethodRefs := make([]any, 0)

	for _, key := range keys {
		vm := map[string]any{
			"id":           key.KeyID,
			"type":         "JsonWebKey2020",
			"controller":   did,
			"publicKeyJwk": key.PublicKeyJwk,
		}
		verificationMethods = append(verificationMethods, vm)
		authenticationRefs = append(authenticationRefs, key.KeyID)
		assertionMethodRefs = append(assertionMethodRefs, key.KeyID)
	}

	return map[string]any{
		"@context":           []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":                 did,
		"verificationMethod": verificationMethods,
		"authentication":     authenticationRefs,
		"assertionMethod":    assertionMethodRefs,
	}
}

// =============================================================================
// did:web Resolution Tests (Mock)
// =============================================================================

func TestDIDWeb_Resolution_BasicDomain(t *testing.T) {
	// Test basic did:web resolution for a simple domain
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := "did:web:example.com"
	keyID := did + "#key-1"

	keys := []DIDKeyTestCase{
		{
			KeyID:        keyID,
			KeyType:      "Ed25519",
			PublicKeyJwk: Ed25519ToJWK(pubKey),
			ExpectTrust:  true,
			Role:         "issuer",
		},
	}
	didDoc := createMockDIDDocument(did, keys)

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test key resolution
	resolvedKey, err := resolver.ResolveEd25519(keyID)
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Error("resolved key doesn't match original")
	}

	// Test trust evaluation
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Error("expected key to be trusted")
	}
}

func TestDIDWeb_Resolution_DomainWithPath(t *testing.T) {
	// Test did:web with path: did:web:example.com:users:alice
	// This maps to https://example.com/users/alice/did.json
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := "did:web:example.com:users:alice"
	keyID := did + "#key-1"

	keys := []DIDKeyTestCase{
		{
			KeyID:        keyID,
			KeyType:      "Ed25519",
			PublicKeyJwk: Ed25519ToJWK(pubKey),
			ExpectTrust:  true,
		},
	}
	didDoc := createMockDIDDocument(did, keys)

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		// Verify the subject ID matches the expected DID or key ID
		if req.Subject.ID != did && req.Subject.ID != keyID {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{
						"error": "unexpected subject ID: " + req.Subject.ID,
					},
				},
			}, nil
		}
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	resolvedKey, err := resolver.ResolveEd25519(keyID)
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Error("resolved key doesn't match original")
	}
}

func TestDIDWeb_Resolution_MultipleKeys(t *testing.T) {
	// Test did:web document with multiple verification methods
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	ecdsaPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey := &ecdsaPrivKey.PublicKey
	ecdsaJWK, _ := ECDSAToJWK(ecdsaKey)

	did := "did:web:multi-key.example.org"

	keys := []DIDKeyTestCase{
		{
			KeyID:        did + "#auth-key",
			KeyType:      "Ed25519",
			PublicKeyJwk: Ed25519ToJWK(ed25519Key),
			ExpectTrust:  true,
			Role:         "authentication",
		},
		{
			KeyID:        did + "#signing-key",
			KeyType:      "ECDSA",
			Curve:        "P-256",
			PublicKeyJwk: ecdsaJWK,
			ExpectTrust:  true,
			Role:         "assertionMethod",
		},
	}
	didDoc := createMockDIDDocument(did, keys)

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Resolve Ed25519 key
	resolvedEd25519, err := resolver.ResolveEd25519(did + "#auth-key")
	if err != nil {
		t.Fatalf("failed to resolve Ed25519 key: %v", err)
	}
	if !ed25519Key.Equal(resolvedEd25519) {
		t.Error("Ed25519 key mismatch")
	}

	// Resolve ECDSA key
	resolvedECDSA, err := resolver.ResolveECDSA(did + "#signing-key")
	if err != nil {
		t.Fatalf("failed to resolve ECDSA key: %v", err)
	}
	if !ecdsaKey.Equal(resolvedECDSA) {
		t.Error("ECDSA key mismatch")
	}
}

// =============================================================================
// did:web Trust Evaluation Tests
// =============================================================================

func TestDIDWeb_TrustEvaluation_TrustedIssuer(t *testing.T) {
	// Test trust evaluation for a trusted issuer
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := "did:web:trusted-issuer.example.com"

	// Server that trusts specific DIDs as issuers
	trustedIssuers := map[string]bool{
		"did:web:trusted-issuer.example.com": true,
		"did:web:another-trusted.org":        true,
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		// Check if the DID is in the trusted issuers list
		if trustedIssuers[req.Subject.ID] {
			return &authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{
						"trusted_as": "issuer",
						"registry":   "trusted-issuers",
					},
				},
			}, nil
		}
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error": "not in trusted issuers list",
				},
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Trusted DID should be accepted
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Error("expected trusted issuer to be trusted")
	}

	// Untrusted DID should be rejected
	trusted, err = resolver.EvaluateTrustEd25519(t.Context(), "did:web:untrusted.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if trusted {
		t.Error("expected untrusted DID to be rejected")
	}
}

func TestDIDWeb_TrustEvaluation_RoleBased(t *testing.T) {
	// Test role-based trust evaluation
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := "did:web:role-test.example.com"

	// Server that trusts based on role
	allowedRoles := map[string][]string{
		"did:web:role-test.example.com": {"issuer", "verifier"},
		"did:web:issuer-only.com":       {"issuer"},
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		roles, exists := allowedRoles[req.Subject.ID]
		if !exists {
			return &authzen.EvaluationResponse{Decision: false}, nil
		}

		// Check if the requested role is allowed
		requestedRole := ""
		if req.Action != nil {
			requestedRole = req.Action.Name
		}

		if requestedRole == "" {
			// No role specified - allow
			return &authzen.EvaluationResponse{Decision: true}, nil
		}

		if slices.Contains(roles, requestedRole) {
			return &authzen.EvaluationResponse{Decision: true}, nil
		}

		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error":          "role not allowed",
					"requested_role": requestedRole,
					"allowed_roles":  roles,
				},
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test allowed role
	trusted, _ := resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "issuer")
	if !trusted {
		t.Error("expected 'issuer' role to be trusted")
	}

	trusted, _ = resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "verifier")
	if !trusted {
		t.Error("expected 'verifier' role to be trusted")
	}

	// Test disallowed role
	trusted, _ = resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "admin")
	if trusted {
		t.Error("expected 'admin' role to be rejected")
	}
}

// =============================================================================
// DID Method Test Vector Support
// =============================================================================
//
// These tests demonstrate how to integrate external test vectors.
// The test case structure is designed to be populated from JSON/YAML test vector files.

func TestDIDMethod_TestVectorFramework(t *testing.T) {
	// This test demonstrates the test vector framework
	// In practice, test cases would be loaded from external files

	testCases := []DIDTestCase{
		{
			Name:   "did:web basic domain",
			DID:    "did:web:example.com",
			Method: "web",
			Keys: []DIDKeyTestCase{
				{
					KeyID:       "did:web:example.com#key-1",
					KeyType:     "Ed25519",
					ExpectTrust: true,
					Role:        "issuer",
				},
			},
			ExpectError: false,
		},
		{
			Name:   "did:web with path",
			DID:    "did:web:example.com:users:alice",
			Method: "web",
			Keys: []DIDKeyTestCase{
				{
					KeyID:       "did:web:example.com:users:alice#signing-key",
					KeyType:     "ECDSA",
					Curve:       "P-256",
					ExpectTrust: true,
					Role:        "assertionMethod",
				},
			},
			ExpectError: false,
		},
		{
			Name:   "did:web with port",
			DID:    "did:web:localhost%3A8080",
			Method: "web",
			Keys: []DIDKeyTestCase{
				{
					KeyID:       "did:web:localhost%3A8080#key-1",
					KeyType:     "Ed25519",
					ExpectTrust: true,
				},
			},
			ExpectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runDIDTestCase(t, tc)
		})
	}
}

// runDIDTestCase executes a single DID test case
func runDIDTestCase(t *testing.T, tc DIDTestCase) {
	t.Helper()

	// Generate keys for the test case
	keys := make([]DIDKeyTestCase, len(tc.Keys))
	keyMap := make(map[string]any) // keyID -> public key

	for i, keyTC := range tc.Keys {
		keys[i] = keyTC

		switch keyTC.KeyType {
		case "Ed25519":
			pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
			keys[i].PublicKeyJwk = Ed25519ToJWK(pubKey)
			keyMap[keyTC.KeyID] = pubKey
		case "ECDSA":
			var curve elliptic.Curve
			switch keyTC.Curve {
			case "P-384":
				curve = elliptic.P384()
			case "P-521":
				curve = elliptic.P521()
			default:
				curve = elliptic.P256()
			}
			privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
			jwk, _ := ECDSAToJWK(&privKey.PublicKey)
			keys[i].PublicKeyJwk = jwk
			keyMap[keyTC.KeyID] = &privKey.PublicKey
		}
	}

	// Create mock DID document
	didDoc := createMockDIDDocument(tc.DID, keys)

	// Create test server
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		if tc.ExpectError {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]any{
						"error": tc.ErrorMatch,
					},
				},
			}, nil
		}
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test each key in the test case
	for i, keyTC := range keys {
		pubKey := keyMap[tc.Keys[i].KeyID]

		switch keyTC.KeyType {
		case "Ed25519":
			resolvedKey, err := resolver.ResolveEd25519(keyTC.KeyID)
			if tc.ExpectError {
				if err == nil {
					t.Errorf("expected error for key %s", keyTC.KeyID)
				}
				return
			}
			if err != nil {
				t.Errorf("failed to resolve Ed25519 key %s: %v", keyTC.KeyID, err)
				continue
			}
			if !pubKey.(ed25519.PublicKey).Equal(resolvedKey) {
				t.Errorf("Ed25519 key mismatch for %s", keyTC.KeyID)
			}

		case "ECDSA":
			resolvedKey, err := resolver.ResolveECDSA(keyTC.KeyID)
			if tc.ExpectError {
				if err == nil {
					t.Errorf("expected error for key %s", keyTC.KeyID)
				}
				return
			}
			if err != nil {
				t.Errorf("failed to resolve ECDSA key %s: %v", keyTC.KeyID, err)
				continue
			}
			if !pubKey.(*ecdsa.PublicKey).Equal(resolvedKey) {
				t.Errorf("ECDSA key mismatch for %s", keyTC.KeyID)
			}
		}
	}
}

// =============================================================================
// did:web Real Resolution Preparation
// =============================================================================
//
// The following tests prepare for actual did:web resolution by testing
// the testserver's ability to serve as both:
// 1. An AuthZEN PDP (Policy Decision Point)
// 2. A DID document server (serving /.well-known/did.json)
//
// For actual did:web resolution, we need to:
// 1. Start an HTTP(S) server that serves DID documents
// 2. Configure go-trust's did:web registry to resolve from that server
// 3. Run the testserver with the did:web registry

func TestDIDWeb_PrepareForRealResolution(t *testing.T) {
	// This test verifies the DID document structure is valid
	// for real did:web resolution scenarios
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := "did:web:test.siros.foundation"
	keyID := did + "#key-1"

	// Create a properly structured DID document
	didDoc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": did,
		"verificationMethod": []any{
			map[string]any{
				"id":         keyID,
				"type":       "JsonWebKey2020",
				"controller": did,
				"publicKeyJwk": map[string]any{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   Ed25519ToJWK(pubKey)["x"],
				},
			},
		},
		"authentication":  []any{keyID},
		"assertionMethod": []any{keyID},
	}

	// Verify structure matches W3C DID Core expectations
	if didDoc["id"] != did {
		t.Error("DID document id mismatch")
	}

	vms, ok := didDoc["verificationMethod"].([]any)
	if !ok || len(vms) == 0 {
		t.Error("DID document must have verification methods")
	}

	vm := vms[0].(map[string]any)
	if vm["id"] != keyID {
		t.Error("verification method id mismatch")
	}
	if vm["type"] != "JsonWebKey2020" {
		t.Error("verification method type should be JsonWebKey2020")
	}
	if vm["controller"] != did {
		t.Error("verification method controller should match DID")
	}

	// Test with mock server
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())
	resolvedKey, err := resolver.ResolveEd25519(keyID)
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Error("key mismatch")
	}
}

// =============================================================================
// Singapore Test Vector Preparation
// =============================================================================
//
// The following structures and tests prepare for integration with
// Singapore test vectors. These test vectors use actual did:web DIDs
// and require real HTTP resolution.

// SingaporeTestVector represents a test vector from the Singapore test suite.
// This structure is designed to match the expected test vector format.
type SingaporeTestVector struct {
	ID           string         `json:"id"`
	Description  string         `json:"description"`
	DID          string         `json:"did"`
	DIDDocument  map[string]any `json:"didDocument"`
	Credentials  []any          `json:"credentials,omitempty"`
	ExpectValid  bool           `json:"expectValid"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
}

func TestSingaporeTestVector_Framework(t *testing.T) {
	// This test demonstrates the framework for running Singapore test vectors
	// Actual test vectors would be loaded from JSON files

	// Example test vector structure (would be loaded from file)
	testVector := SingaporeTestVector{
		ID:          "sg-test-001",
		Description: "Basic did:web resolution with Ed25519 key",
		DID:         "did:web:test.example.sg",
		DIDDocument: map[string]any{
			"@context": []any{
				"https://www.w3.org/ns/did/v1",
			},
			"id": "did:web:test.example.sg",
			"verificationMethod": []any{
				map[string]any{
					"id":         "did:web:test.example.sg#key-1",
					"type":       "JsonWebKey2020",
					"controller": "did:web:test.example.sg",
					"publicKeyJwk": map[string]any{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", // Example base64url
					},
				},
			},
		},
		ExpectValid: true,
	}

	// Create server that returns the test vector's DID document
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: testVector.ExpectValid,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: testVector.DIDDocument,
			},
		}, nil
	}))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test resolution
	_, err := resolver.ResolveEd25519(testVector.DID + "#key-1")
	if testVector.ExpectValid {
		if err != nil {
			t.Errorf("expected valid resolution, got error: %v", err)
		}
	} else {
		if err == nil {
			t.Error("expected resolution to fail")
		}
	}
}

// =============================================================================
// Utility Functions for Test Vectors
// =============================================================================

// loadTestVectorsFromJSON loads test vectors from a JSON file.
// This is a placeholder for future implementation.
func loadTestVectorsFromJSON(path string) ([]SingaporeTestVector, error) {
	// TODO: Implement JSON loading when integrating actual test vectors
	return nil, nil
}

// validateDIDDocument checks if a DID document structure is valid.
func validateDIDDocument(doc map[string]any) error {
	// Check required fields
	if _, ok := doc["@context"]; !ok {
		return errors.New("DID document missing @context")
	}
	if _, ok := doc["id"]; !ok {
		return errors.New("DID document missing id")
	}
	return nil
}

func TestValidateDIDDocument(t *testing.T) {
	tests := []struct {
		name    string
		doc     map[string]any
		wantErr bool
	}{
		{
			name: "valid document",
			doc: map[string]any{
				"@context": []string{"https://www.w3.org/ns/did/v1"},
				"id":       "did:web:example.com",
			},
			wantErr: false,
		},
		{
			name: "missing context",
			doc: map[string]any{
				"id": "did:web:example.com",
			},
			wantErr: true,
		},
		{
			name: "missing id",
			doc: map[string]any{
				"@context": []string{"https://www.w3.org/ns/did/v1"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDIDDocument(tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDIDDocument() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Real did:web Resolution Tests using DIDWebRegistry
// =============================================================================
//
// These tests use the actual go-trust did:web registry with an embedded HTTP
// server to test real DID resolution. This approach:
// 1. Starts an HTTP server that serves DID documents
// 2. Creates a DIDWebRegistry configured to trust the test server
// 3. Uses testserver.WithRegistry() to add the real registry
// 4. Tests actual DID resolution through the full stack

// DIDWebTestServer is a helper that creates an HTTP server serving DID documents
// and provides the corresponding did:web DID for the server.
type DIDWebTestServer struct {
	HTTPServer   *httptest.Server
	DIDDocuments map[string]map[string]any // path -> DID document
}

// NewDIDWebTestServer creates a new test server for did:web resolution.
func NewDIDWebTestServer() *DIDWebTestServer {
	ts := &DIDWebTestServer{
		DIDDocuments: make(map[string]map[string]any),
	}

	ts.HTTPServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request for debugging
		path := r.URL.Path

		// Look up the DID document for this path
		doc, ok := ts.DIDDocuments[path]
		if !ok {
			http.Error(w, "DID document not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/did+json")
		json.NewEncoder(w).Encode(doc) // #nosec G104
	}))

	return ts
}

// Close shuts down the test server.
func (ts *DIDWebTestServer) Close() {
	ts.HTTPServer.Close()
}

// DID returns the did:web DID for the test server's root.
// For example: did:web:127.0.0.1%3A12345
func (ts *DIDWebTestServer) DID() string {
	u, _ := url.Parse(ts.HTTPServer.URL)
	// Encode the port colon as %3A per did:web spec
	host := strings.Replace(u.Host, ":", "%3A", 1)
	return "did:web:" + host
}

// DIDWithPath returns a did:web DID with a path component.
// For example: did:web:127.0.0.1%3A12345:users:alice
func (ts *DIDWebTestServer) DIDWithPath(pathParts ...string) string {
	return ts.DID() + ":" + strings.Join(pathParts, ":")
}

// AddDIDDocument adds a DID document to be served at the root /.well-known/did.json
func (ts *DIDWebTestServer) AddDIDDocument(did string, doc map[string]any) {
	// Ensure the document has the correct ID
	doc["id"] = did
	ts.DIDDocuments["/.well-known/did.json"] = doc
}

// AddDIDDocumentWithPath adds a DID document at a specific path.
// The path should be like "/users/alice/did.json"
func (ts *DIDWebTestServer) AddDIDDocumentWithPath(path string, did string, doc map[string]any) {
	doc["id"] = did
	ts.DIDDocuments[path] = doc
}

// CreateDIDWebRegistry creates a DIDWebRegistry configured to work with this test server.
func (ts *DIDWebTestServer) CreateDIDWebRegistry() (*didweb.DIDWebRegistry, error) {
	registry, err := didweb.NewDIDWebRegistry(didweb.Config{
		InsecureSkipVerify: true, // Disable TLS verification for testing
		AllowHTTP:          true, // Allow HTTP instead of HTTPS for testing
		Description:        "Test DID Web Registry",
	})
	if err != nil {
		return nil, err
	}

	// Use the test server's HTTP client
	registry.SetHTTPClient(ts.HTTPServer.Client())

	return registry, nil
}

// =============================================================================
// Real did:web Resolution Tests
// =============================================================================

func TestRealDIDWeb_Resolution_BasicDomain(t *testing.T) {
	// Create test server
	ts := NewDIDWebTestServer()
	defer ts.Close()

	// Generate a key
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := ts.DID()
	keyID := did + "#key-1"

	// Create and add DID document
	didDoc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": did,
		"verificationMethod": []any{
			map[string]any{
				"id":           keyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
		"authentication":  []any{keyID},
		"assertionMethod": []any{keyID},
	}
	ts.AddDIDDocument(did, didDoc)

	// Create did:web registry
	registry, err := ts.CreateDIDWebRegistry()
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create testserver with the real did:web registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver
	resolver := NewGoTrustResolver(srv.URL())

	// Test key resolution - this goes through the full stack:
	// resolver -> testserver -> did:web registry -> HTTP server -> DID document
	resolvedKey, err := resolver.ResolveEd25519(keyID)
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Error("resolved key doesn't match original")
	}
}

func TestRealDIDWeb_Resolution_WithPath(t *testing.T) {
	// Test did:web with path: did:web:host:users:alice
	ts := NewDIDWebTestServer()
	defer ts.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := ts.DIDWithPath("users", "alice")
	keyID := did + "#signing-key"

	didDoc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
		},
		"id": did,
		"verificationMethod": []any{
			map[string]any{
				"id":           keyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}
	ts.AddDIDDocumentWithPath("/users/alice/did.json", did, didDoc)

	registry, err := ts.CreateDIDWebRegistry()
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	resolvedKey, err := resolver.ResolveEd25519(keyID)
	if err != nil {
		t.Fatalf("failed to resolve key with path: %v", err)
	}
	if !pubKey.Equal(resolvedKey) {
		t.Error("resolved key doesn't match original")
	}
}

func TestRealDIDWeb_Resolution_MultipleKeys(t *testing.T) {
	ts := NewDIDWebTestServer()
	defer ts.Close()

	// Generate multiple keys
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	ecdsaPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey := &ecdsaPrivKey.PublicKey
	ecdsaJWK, _ := ECDSAToJWK(ecdsaKey)

	did := ts.DID()
	authKeyID := did + "#auth-key"
	signingKeyID := did + "#signing-key"

	didDoc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
		},
		"id": did,
		"verificationMethod": []any{
			map[string]any{
				"id":           authKeyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(ed25519Key),
			},
			map[string]any{
				"id":           signingKeyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": ecdsaJWK,
			},
		},
		"authentication":  []any{authKeyID},
		"assertionMethod": []any{signingKeyID},
	}
	ts.AddDIDDocument(did, didDoc)

	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Resolve Ed25519 key
	resolvedEd25519, err := resolver.ResolveEd25519(authKeyID)
	if err != nil {
		t.Fatalf("failed to resolve Ed25519 key: %v", err)
	}
	if !ed25519Key.Equal(resolvedEd25519) {
		t.Error("Ed25519 key mismatch")
	}

	// Resolve ECDSA key
	resolvedECDSA, err := resolver.ResolveECDSA(signingKeyID)
	if err != nil {
		t.Fatalf("failed to resolve ECDSA key: %v", err)
	}
	if !ecdsaKey.Equal(resolvedECDSA) {
		t.Error("ECDSA key mismatch")
	}
}

func TestRealDIDWeb_TrustEvaluation(t *testing.T) {
	ts := NewDIDWebTestServer()
	defer ts.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := ts.DID()
	keyID := did + "#key-1"

	didDoc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/did/v1"},
		"id":       did,
		"verificationMethod": []any{
			map[string]any{
				"id":           keyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}
	ts.AddDIDDocument(did, didDoc)

	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// The did:web registry validates that the key is in the DID document
	// This is the "trust" aspect - if the key matches, it's trusted
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), did, pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Error("expected key to be trusted (it's in the DID document)")
	}
}

func TestRealDIDWeb_Resolution_NotFound(t *testing.T) {
	ts := NewDIDWebTestServer()
	defer ts.Close()

	// Don't add any DID documents - the server will return 404

	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	did := ts.DID()
	_, err := resolver.ResolveEd25519(did + "#key-1")
	if err == nil {
		t.Fatal("expected error for non-existent DID")
	}
}

func TestRealDIDWeb_Resolution_KeyNotInDocument(t *testing.T) {
	ts := NewDIDWebTestServer()
	defer ts.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := ts.DID()

	// Create DID document with key-1
	didDoc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/did/v1"},
		"id":       did,
		"verificationMethod": []any{
			map[string]any{
				"id":           did + "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}
	ts.AddDIDDocument(did, didDoc)

	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Try to resolve key-2 which doesn't exist in the document
	_, err := resolver.ResolveEd25519(did + "#key-2")
	if err == nil {
		t.Fatal("expected error for non-existent key")
	}
}

// =============================================================================
// Integration Test: Full Credential Verification Flow with Real did:web
// =============================================================================

func TestRealDIDWeb_Integration_CredentialVerificationFlow(t *testing.T) {
	// This test simulates a complete credential verification flow:
	// 1. Issuer has a did:web DID with public key
	// 2. Verifier resolves issuer's DID document
	// 3. Verifier extracts issuer's public key
	// 4. Verifier validates trust in issuer
	// 5. Verifier can now verify credential signature

	ts := NewDIDWebTestServer()
	defer ts.Close()

	// Setup: Issuer creates a DID document with their signing key
	issuerKey, _, _ := ed25519.GenerateKey(rand.Reader)
	issuerDID := ts.DID()
	issuerKeyID := issuerDID + "#signing-key"

	issuerDIDDoc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": issuerDID,
		"verificationMethod": []any{
			map[string]any{
				"id":           issuerKeyID,
				"type":         "JsonWebKey2020",
				"controller":   issuerDID,
				"publicKeyJwk": Ed25519ToJWK(issuerKey),
			},
		},
		"authentication":  []any{issuerKeyID},
		"assertionMethod": []any{issuerKeyID},
	}
	ts.AddDIDDocument(issuerDID, issuerDIDDoc)

	// Create the trust infrastructure
	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Step 1: Verifier receives a credential with issuer DID
	t.Log("Verifier received credential from issuer:", issuerDID)

	// Step 2: Resolve issuer's DID document and extract public key
	resolvedKey, err := resolver.ResolveEd25519(issuerKeyID)
	if err != nil {
		t.Fatalf("Failed to resolve issuer key: %v", err)
	}
	t.Log("Resolved issuer's public key from DID document")

	// Step 3: Verify the key matches what we expect
	if !issuerKey.Equal(resolvedKey) {
		t.Fatal("Resolved key doesn't match expected issuer key")
	}
	t.Log("Key verification successful")

	// Step 4: Validate trust in the issuer (the did:web registry does this
	// by verifying the key is in the DID document at the expected domain)
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), issuerDID, issuerKey, "assertionMethod")
	if err != nil {
		t.Fatalf("Trust evaluation failed: %v", err)
	}
	if !trusted {
		t.Fatal("Issuer key is not trusted")
	}
	t.Log("Trust evaluation successful - issuer is trusted")

	// At this point, the verifier can use resolvedKey to verify the credential signature
	t.Log("Integration test complete - ready for signature verification")
}

// =============================================================================
// Test Helpers for Singapore Test Vectors (Real Resolution)
// =============================================================================

// RunSingaporeTestVectorWithRealResolution runs a Singapore test vector using
// actual HTTP did:web resolution instead of mocking.
func RunSingaporeTestVectorWithRealResolution(t *testing.T, tv SingaporeTestVector) {
	t.Helper()

	// Create test server
	ts := NewDIDWebTestServer()
	defer ts.Close()

	// Add the test vector's DID document to our test server
	// We need to adapt the DID to match our test server's address
	testDID := ts.DID()
	testKeyID := testDID + "#key-1"

	// Copy the DID document structure but update IDs
	adaptedDoc := make(map[string]any)
	maps.Copy(adaptedDoc, tv.DIDDocument)
	adaptedDoc["id"] = testDID

	// Update verification method IDs
	if vms, ok := adaptedDoc["verificationMethod"].([]any); ok {
		for i, vm := range vms {
			if vmMap, ok := vm.(map[string]any); ok {
				// Update the key ID to use our test server's DID
				if _, hasID := vmMap["id"]; hasID {
					vmMap["id"] = testKeyID
				}
				vmMap["controller"] = testDID
				vms[i] = vmMap
			}
		}
	}

	ts.AddDIDDocument(testDID, adaptedDoc)

	// Create the trust infrastructure
	registry, err := ts.CreateDIDWebRegistry()
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	// Test resolution
	_, err = resolver.ResolveEd25519(testKeyID)
	if tv.ExpectValid {
		if err != nil {
			t.Errorf("expected valid resolution, got error: %v", err)
		}
	} else {
		if err == nil {
			t.Error("expected resolution to fail")
		}
	}
}

func TestRealDIDWeb_SingaporeTestVector_Adapted(t *testing.T) {
	// Example of running a Singapore test vector with real resolution
	tv := SingaporeTestVector{
		ID:          "sg-adapted-001",
		Description: "Singapore test vector with real did:web resolution",
		DID:         "did:web:test.example.sg", // Will be adapted to test server
		DIDDocument: map[string]any{
			"@context": []any{
				"https://www.w3.org/ns/did/v1",
			},
			"id": "did:web:test.example.sg",
			"verificationMethod": []any{
				map[string]any{
					"id":         "did:web:test.example.sg#key-1",
					"type":       "JsonWebKey2020",
					"controller": "did:web:test.example.sg",
					"publicKeyJwk": map[string]any{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
					},
				},
			},
		},
		ExpectValid: true,
	}

	RunSingaporeTestVectorWithRealResolution(t, tv)
}

// =============================================================================
// Benchmark Tests for Real did:web Resolution
// =============================================================================

func BenchmarkRealDIDWeb_Resolution(b *testing.B) {
	ts := NewDIDWebTestServer()
	defer ts.Close()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	did := ts.DID()
	keyID := did + "#key-1"

	didDoc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/did/v1"},
		"id":       did,
		"verificationMethod": []any{
			map[string]any{
				"id":           keyID,
				"type":         "JsonWebKey2020",
				"controller":   did,
				"publicKeyJwk": Ed25519ToJWK(pubKey),
			},
		},
	}
	ts.AddDIDDocument(did, didDoc)

	registry, _ := ts.CreateDIDWebRegistry()
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := NewGoTrustResolver(srv.URL())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := resolver.ResolveEd25519(keyID)
		if err != nil {
			b.Fatalf("resolution failed: %v", err)
		}
	}
}
