package keyresolver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestNewGoTrustEvaluator(t *testing.T) {
	evaluator := NewGoTrustEvaluator("https://pdp.example.com")
	if evaluator == nil {
		t.Fatal("expected non-nil evaluator")
	}
	if evaluator.GetClient() == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestGoTrustEvaluator_EvaluateTrust(t *testing.T) {
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true}) // #nosec G104
	}))
	defer server.Close()

	evaluator := NewGoTrustEvaluator(server.URL)
	trusted, err := evaluator.EvaluateTrust("did:web:example.com", pubKey, "issuer")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestGoTrustEvaluator_EvaluateTrustWithContext(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true}) // #nosec G104
	}))
	defer server.Close()

	evaluator := NewGoTrustEvaluator(server.URL)
	trusted, err := evaluator.EvaluateTrustWithContext(t.Context(), "did:web:example.com", pubKey, "")
	if err != nil {
		t.Fatalf("failed to evaluate trust: %v", err)
	}
	if !trusted {
		t.Fatal("expected trusted decision")
	}
}

func TestValidatingResolver_ResolveEd25519(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a static resolver with the key
	staticResolver := NewStaticResolver()
	staticResolver.AddKey("did:web:example.com#key-1", pubKey)

	// Create a mock trust evaluator that always returns true
	mockEvaluator := &mockTrustEvaluator{decision: true}

	validatingResolver := NewValidatingResolver(staticResolver, mockEvaluator, "")

	resolvedKey, err := validatingResolver.ResolveEd25519("did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("failed to resolve key: %v", err)
	}

	if !pubKey.Equal(resolvedKey) {
		t.Fatal("resolved key doesn't match original")
	}
}

func TestValidatingResolver_ResolveEd25519_NotTrusted(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	staticResolver := NewStaticResolver()
	staticResolver.AddKey("did:web:example.com#key-1", pubKey)

	// Create a mock trust evaluator that always returns false
	mockEvaluator := &mockTrustEvaluator{decision: false}

	validatingResolver := NewValidatingResolver(staticResolver, mockEvaluator, "issuer")

	_, err = validatingResolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error for untrusted key")
	}
}

func TestValidatingResolver_ResolveEd25519_ResolutionError(t *testing.T) {
	staticResolver := NewStaticResolver() // Empty resolver

	mockEvaluator := &mockTrustEvaluator{decision: true}

	validatingResolver := NewValidatingResolver(staticResolver, mockEvaluator, "")

	_, err := validatingResolver.ResolveEd25519("did:web:example.com#key-1")
	if err == nil {
		t.Fatal("expected error when key not found")
	}
}

// mockTrustEvaluator is a test helper
type mockTrustEvaluator struct {
	decision bool
	err      error
}

func (m *mockTrustEvaluator) EvaluateTrust(subjectID string, publicKey ed25519.PublicKey, role string) (bool, error) {
	return m.decision, m.err
}
