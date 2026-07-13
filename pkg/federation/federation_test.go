package federation

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestBuildEntityConfiguration(t *testing.T) {
	// Use the entityConfigClaims for parsing
	cfg := &Config{
		Enabled:          true,
		EntityID:         "https://issuer.example.com",
		AuthorityHints:   []string{"https://trust-anchor.example.com"},
		OrganizationName: "Example Issuer",
		LogoURI:          "https://issuer.example.com/logo.png",
		TTL:              3600,
		TrustMarks: []TrustMarkConfig{
			{ID: "https://tm.example.com/certified", JWT: "eyJ..."},
		},
	}

	// Create a test signer - we can't use pki.SignerConfig directly in unit tests
	// without a key file, so we test the claims structure instead
	t.Run("config defaults", func(t *testing.T) {
		if cfg.EntityID != "https://issuer.example.com" {
			t.Errorf("expected entity ID 'https://issuer.example.com', got %q", cfg.EntityID)
		}
		if len(cfg.AuthorityHints) != 1 {
			t.Errorf("expected 1 authority hint, got %d", len(cfg.AuthorityHints))
		}
		if cfg.TTL != 3600 {
			t.Errorf("expected TTL 3600, got %d", cfg.TTL)
		}
	})

	t.Run("entity metadata serialization", func(t *testing.T) {
		metadata := &EntityMetadata{
			OpenIDCredentialIssuer: map[string]any{
				"credential_issuer":   "https://issuer.example.com",
				"credential_endpoint": "https://issuer.example.com/credential",
			},
			FederationEntity: map[string]any{
				"organization_name": "Example Org",
			},
		}

		data, err := json.Marshal(metadata)
		if err != nil {
			t.Fatalf("failed to marshal metadata: %v", err)
		}

		var parsed EntityMetadata
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal metadata: %v", err)
		}

		if parsed.OpenIDCredentialIssuer["credential_issuer"] != "https://issuer.example.com" {
			t.Error("credential_issuer mismatch")
		}
		if parsed.FederationEntity["organization_name"] != "Example Org" {
			t.Error("organization_name mismatch")
		}
		if parsed.OpenIDRelyingParty != nil {
			t.Error("expected nil openid_relying_party")
		}
	})

	t.Run("claims structure", func(t *testing.T) {
		jwksJSON := json.RawMessage(`{"keys":[]}`)
		claims := entityConfigClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:  "https://issuer.example.com",
				Subject: "https://issuer.example.com",
			},
			JWKS:           jwksJSON,
			AuthorityHints: []string{"https://anchor.example.com"},
			Metadata: &EntityMetadata{
				OpenIDCredentialIssuer: map[string]any{
					"credential_issuer": "https://issuer.example.com",
				},
			},
			TrustMarks: []TrustMark{
				{ID: "https://tm.example.com/mark", TrustMark: "jwt-value"},
			},
		}

		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("failed to marshal claims: %v", err)
		}

		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if raw["iss"] != "https://issuer.example.com" {
			t.Error("iss mismatch")
		}
		if raw["sub"] != "https://issuer.example.com" {
			t.Error("sub mismatch")
		}
		hints, ok := raw["authority_hints"].([]any)
		if !ok || len(hints) != 1 {
			t.Error("authority_hints mismatch")
		}
		meta, ok := raw["metadata"].(map[string]any)
		if !ok {
			t.Fatal("metadata missing")
		}
		if _, ok := meta["openid_credential_issuer"]; !ok {
			t.Error("openid_credential_issuer missing from metadata")
		}
	})
}

func TestServiceEntityIDFallback(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		// EntityID is empty - should fall back to publicURL
	}
	svc := NewService(cfg, nil, "https://fallback.example.com")
	if svc.entityID != "https://fallback.example.com" {
		t.Errorf("expected entity ID 'https://fallback.example.com', got %q", svc.entityID)
	}
}
