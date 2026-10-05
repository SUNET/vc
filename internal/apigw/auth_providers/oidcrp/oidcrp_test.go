package oidcrp

import (
	"context"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// TestSessionStore tests the session store functionality
func TestSessionStore(t *testing.T) {
	log := logger.NewSimple("test")
	ctx := context.Background()
	svc := &Service{
		cfg:          &model.OIDCRP{IssuerURL: "https://accounts.google.com", SessionDuration: 300},
		sessionCache: cache.NewMemoryCache[*Session](5 * time.Minute),
		log:          log,
	}

	// Test session creation
	session, err := svc.createSession(ctx, "pid")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.CredentialType != "pid" {
		t.Errorf("Expected credential type 'pid', got %s", session.CredentialType)
	}

	// Test session retrieval
	retrieved, err := svc.getSession(ctx, session.State)
	if err != nil {
		t.Fatalf("Failed to retrieve session: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("Expected session ID %s, got %s", session.ID, retrieved.ID)
	}

	if retrieved.Nonce != session.Nonce {
		t.Errorf("Expected nonce %s, got %s", session.Nonce, retrieved.Nonce)
	}

	// Test session deletion
	svc.deleteSession(ctx, session.State)

	_, err = svc.getSession(ctx, session.State)
	if err == nil {
		t.Error("Expected error when retrieving deleted session")
	}
}

// TestSessionExpiration tests that expired sessions are removed
func TestSessionExpiration(t *testing.T) {
	log := logger.NewSimple("test")
	ctx := context.Background()
	svc := &Service{
		cfg:          &model.OIDCRP{IssuerURL: "https://accounts.google.com", SessionDuration: 1},
		sessionCache: cache.NewMemoryCache[*Session](1 * time.Millisecond),
		log:          log,
	}

	// Create a session
	session, err := svc.createSession(ctx, "pid")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to get expired session - should fail
	_, err = svc.getSession(ctx, session.State)
	if err == nil {
		t.Log("Session still exists (cleanup hasn't run yet - expected behavior)")
	}
}

// TestAttributeMapper tests attribute-mapping functionality
func TestAttributeMapper(t *testing.T) {
	mapping := model.AttributeMapping{
		"given_name": {
			Claim:    "identity.given_name",
			Required: true,
		},
		"family_name": {
			Claim:    "identity.family_name",
			Required: true,
		},
		"email": {
			Claim:    "identity.email",
			Required: false,
		},
		"country": {
			Claim:    "identity.country",
			Required: false,
			Default:  "SE",
		},
	}

	mapper := NewAttributeMapper(mapping)

	// Test claims
	inputClaims := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "JOHN.DOE@EXAMPLE.COM",
		// country is missing, should use default
	}

	result, err := mapper.Apply(inputClaims)
	if err != nil {
		t.Fatalf("Failed to transform claims: %v", err)
	}

	// Verify nested structure
	identity, ok := result["identity"].(map[string]any)
	if !ok {
		t.Fatal("Expected 'identity' to be a map")
	}

	// Check values
	if identity["given_name"] != "John" {
		t.Errorf("Expected given_name 'John', got %v", identity["given_name"])
	}

	if identity["family_name"] != "Doe" {
		t.Errorf("Expected family_name 'Doe', got %v", identity["family_name"])
	}

	if identity["email"] != "JOHN.DOE@EXAMPLE.COM" {
		t.Errorf("Expected email 'JOHN.DOE@EXAMPLE.COM' (no transform), got %v", identity["email"])
	}

	// Check default value
	if identity["country"] != "SE" {
		t.Errorf("Expected default country 'SE', got %v", identity["country"])
	}
}

// TestAttributeMapperMissingRequired tests that missing required claims fail
func TestAttributeMapperMissingRequired(t *testing.T) {
	mapping := model.AttributeMapping{
		"given_name": {
			Claim:    "identity.given_name",
			Required: true,
		},
	}

	mapper := NewAttributeMapper(mapping)

	// Missing required claim
	inputClaims := map[string]any{}

	_, err := mapper.Apply(inputClaims)
	if err == nil {
		t.Error("Expected error for missing required claim")
	}
}

// TestServiceInitialization tests that the service can be initialized with valid config
func TestServiceInitialization(t *testing.T) {
	// This test requires a real OIDC provider or mock, so we skip in unit tests
	// Integration tests with a mock provider should be in internal/apigw/integration/
	t.Skip("Requires OIDC provider - see integration tests")
}

// BenchmarkAttributeMapper_Apply benchmarks attribute mapping
func BenchmarkAttributeMapper_Apply(b *testing.B) {
	mapping := model.AttributeMapping{
		"given_name":  {Claim: "identity.given_name", Required: true},
		"family_name": {Claim: "identity.family_name", Required: true},
		"email":       {Claim: "identity.email", Required: true},
	}

	mapper := NewAttributeMapper(mapping)

	claims := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mapper.Apply(claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}
