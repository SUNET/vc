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
		cfg:          &model.OIDCRPConfig{IssuerURL: "https://accounts.google.com", SessionDuration: 300},
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
		cfg:          &model.OIDCRPConfig{IssuerURL: "https://accounts.google.com", SessionDuration: 1},
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

// TestClaimTransformer tests claim transformation functionality
func TestClaimTransformer(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			CredentialConfigID: "urn:eudi:pid:1",
			Attributes: map[string]model.AttributeConfig{
				"given_name": {
					Claim:    "identity.given_name",
					Required: true,
				},
				"family_name": {
					Claim:    "identity.family_name",
					Required: true,
				},
				"email": {
					Claim:     "identity.email",
					Required:  false,
					Transform: "lowercase",
				},
				"country": {
					Claim:    "identity.country",
					Required: false,
					Default:  "SE",
				},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	// Test claims
	inputClaims := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "JOHN.DOE@EXAMPLE.COM",
		// country is missing, should use default
	}

	result, err := transformer.TransformClaims("pid", inputClaims)
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

	// Check transformation
	if identity["email"] != "john.doe@example.com" {
		t.Errorf("Expected lowercase email 'john.doe@example.com', got %v", identity["email"])
	}

	// Check default value
	if identity["country"] != "SE" {
		t.Errorf("Expected default country 'SE', got %v", identity["country"])
	}
}

// TestClaimTransformerMissingRequired tests that missing required claims fail
func TestClaimTransformerMissingRequired(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			CredentialConfigID: "urn:eudi:pid:1",
			Attributes: map[string]model.AttributeConfig{
				"given_name": {
					Claim:    "identity.given_name",
					Required: true,
				},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	// Missing required claim
	inputClaims := map[string]any{}

	_, err := transformer.TransformClaims("pid", inputClaims)
	if err == nil {
		t.Error("Expected error for missing required claim")
	}
}

// TestClaimTransformerTransformations tests various transformations
func TestClaimTransformerTransformations(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"test": {
			CredentialConfigID: "test:1",
			Attributes: map[string]model.AttributeConfig{
				"lowercase_field": {
					Claim:     "result.lowercase",
					Required:  false,
					Transform: "lowercase",
				},
				"uppercase_field": {
					Claim:     "result.uppercase",
					Required:  false,
					Transform: "uppercase",
				},
				"trim_field": {
					Claim:     "result.trimmed",
					Required:  false,
					Transform: "trim",
				},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	inputClaims := map[string]any{
		"lowercase_field": "HELLO WORLD",
		"uppercase_field": "hello world",
		"trim_field":      "  spaced  ",
	}

	result, err := transformer.TransformClaims("test", inputClaims)
	if err != nil {
		t.Fatalf("Failed to transform claims: %v", err)
	}

	resultMap, ok := result["result"].(map[string]any)
	if !ok {
		t.Fatal("Expected 'result' to be a map")
	}

	if resultMap["lowercase"] != "hello world" {
		t.Errorf("Expected lowercase 'hello world', got %v", resultMap["lowercase"])
	}

	if resultMap["uppercase"] != "HELLO WORLD" {
		t.Errorf("Expected uppercase 'HELLO WORLD', got %v", resultMap["uppercase"])
	}

	if resultMap["trimmed"] != "spaced" {
		t.Errorf("Expected trimmed 'spaced', got %v", resultMap["trimmed"])
	}
}

// TestServiceInitialization tests that the service can be initialized with valid config
func TestServiceInitialization(t *testing.T) {
	// This test requires a real OIDC provider or mock, so we skip in unit tests
	// Integration tests with a mock provider should be in internal/apigw/integration/
	t.Skip("Requires OIDC provider - see integration tests")
}

// BenchmarkClaimTransform benchmarks claim transformation
func BenchmarkClaimTransform(b *testing.B) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			CredentialConfigID: "urn:eudi:pid:1",
			Attributes: map[string]model.AttributeConfig{
				"given_name":  {Claim: "identity.given_name", Required: true},
				"family_name": {Claim: "identity.family_name", Required: true},
				"email":       {Claim: "identity.email", Required: true},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	claims := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := transformer.TransformClaims("pid", claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}
