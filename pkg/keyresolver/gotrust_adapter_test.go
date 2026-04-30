package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

func TestNewGoTrustResolver(t *testing.T) {
	resolver := NewGoTrustResolver("https://pdp.example.com")
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	if resolver.client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewGoTrustResolverWithClient(t *testing.T) {
	client := authzenclient.New("https://pdp.example.com")
	resolver := NewGoTrustResolverWithClient(client)
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	if resolver.GetClient() != client {
		t.Fatal("expected same client")
	}
}

func TestGoTrustResolver_ResolveEd25519(t *testing.T) {
	// Generate a test key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

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

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzen.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify it's a resolution-only request
		if req.Resource.Type != "" {
			t.Errorf("expected resolution-only request, got resource.type=%s", req.Resource.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{ // #nosec G104
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		})
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	resolvedKey, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}

	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestGoTrustResolver_ResolveEd25519_Denied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{ // #nosec G104
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]any{
					"error": "subject not found",
				},
			},
		})
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	_, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error for denied resolution")
	}
	if err.Error() != "resolution denied for did:web:example.com#key-1: subject not found" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGoTrustResolver_ResolveEd25519_NoMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{ // #nosec G104
			Decision: true,
			// No Context or TrustMetadata
		})
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	_, err := resolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error when no metadata")
	}
}

func TestGoTrustResolver_ResolveECDSA(t *testing.T) {
	// Generate a test key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKey := &privKey.PublicKey

	jwk, err := ECDSAToJWK(pubKey)
	if err != nil {
		t.Fatalf("failed to convert key to JWK: %v", err)
	}

	// Create a mock DID document
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{ // #nosec G104
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: didDoc,
			},
		})
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	resolvedKey, err := resolver.ResolveECDSA("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}

	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestGoTrustResolver_EvaluateTrustEd25519(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzen.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify it's a full evaluation request
		if req.Resource.Type != "jwk" {
			t.Errorf("expected jwk resource type, got %s", req.Resource.Type)
		}
		if req.Action == nil || req.Action.Name != "issuer" {
			t.Error("expected action with name 'issuer'")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true}) // #nosec G104
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	trusted, err := resolver.EvaluateTrustEd25519(t.Context(), "did:web:example.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestGoTrustResolver_EvaluateTrustECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzen.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify it's a full evaluation request with ECDSA
		if req.Resource.Type != "jwk" {
			t.Errorf("expected jwk resource type, got %s", req.Resource.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true}) // #nosec G104
	}))
	defer server.Close()

	resolver := NewGoTrustResolver(server.URL)
	trusted, err := resolver.EvaluateTrustECDSA(t.Context(), "did:web:example.com", &privKey.PublicKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestEd25519ToJWK_JWKToEd25519_RoundTrip(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk := Ed25519ToJWK(pubKey)
	if jwk["kty"] != "OKP" {
		t.Errorf("expected kty=OKP, got %v", jwk["kty"])
	}
	if jwk["crv"] != "Ed25519" {
		t.Errorf("expected crv=Ed25519, got %v", jwk["crv"])
	}

	recovered, err := JWKToEd25519(jwk)
	if err != nil {
		t.Fatalf("failed to convert JWK to Ed25519: %v", err)
	}

	if !pubKey.Equal(recovered) {
		t.Fatal("round-trip failed: keys don't match")
	}
}

func TestJWKToEd25519_InvalidKeyType(t *testing.T) {
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
	}
	_, err := JWKToEd25519(jwk)
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestJWKToEd25519_InvalidCurve(t *testing.T) {
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "X25519",
		"x":   "AAAA",
	}
	_, err := JWKToEd25519(jwk)
	if err == nil {
		t.Fatal("expected error for invalid curve")
	}
}

func TestJWKToEd25519_MissingX(t *testing.T) {
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
	}
	_, err := JWKToEd25519(jwk)
	if err == nil {
		t.Fatal("expected error for missing x coordinate")
	}
}

func TestECDSAToJWK_JWKToECDSA_RoundTrip(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	expectedCrvs := []string{"P-256", "P-384", "P-521"}

	for i, curve := range curves {
		t.Run(expectedCrvs[i], func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			jwk, err := ECDSAToJWK(&privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to convert to JWK: %v", err)
			}

			if jwk["kty"] != "EC" {
				t.Errorf("expected kty=EC, got %v", jwk["kty"])
			}
			if jwk["crv"] != expectedCrvs[i] {
				t.Errorf("expected crv=%s, got %v", expectedCrvs[i], jwk["crv"])
			}

			recovered, err := JWKToECDSA(jwk)
			if err != nil {
				t.Fatalf("failed to convert JWK to ECDSA: %v", err)
			}

			if !privKey.PublicKey.Equal(recovered) {
				t.Fatal("round-trip failed: keys don't match")
			}
		})
	}
}

func TestECDSAToJWK_NilKey(t *testing.T) {
	_, err := ECDSAToJWK(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestJWKToECDSA_InvalidKeyType(t *testing.T) {
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
	}
	_, err := JWKToECDSA(jwk)
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestJWKToECDSA_UnsupportedCurve(t *testing.T) {
	jwk := map[string]any{
		"kty": "EC",
		"crv": "secp256k1",
		"x":   "AAAA",
		"y":   "AAAA",
	}
	_, err := JWKToECDSA(jwk)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestJWKToECDSA_MissingCoordinates(t *testing.T) {
	tests := []struct {
		name string
		jwk  map[string]any
	}{
		{"missing x", map[string]any{"kty": "EC", "crv": "P-256", "y": "AAAA"}},
		{"missing y", map[string]any{"kty": "EC", "crv": "P-256", "x": "AAAA"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := JWKToECDSA(tt.jwk)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewGoTrustResolverWithDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/authzen-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.PDPMetadata{ // #nosec G104
				PolicyDecisionPoint:      "https://pdp.example.com",
				AccessEvaluationEndpoint: "https://pdp.example.com/evaluation",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver, err := NewGoTrustResolverWithDiscovery(t.Context(), server.URL)
	if err != nil {
		t.Fatalf("failed to create resolver with discovery: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestNewGoTrustResolverWithDiscovery_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := NewGoTrustResolverWithDiscovery(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected error when discovery fails")
	}
}
