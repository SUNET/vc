package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/go-playground/validator/v10"
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

	// This sub-test only exercises Config field defaults and the claims
	// structure directly; TestBuildEntityConfigurationSignedJWT below
	// exercises BuildEntityConfiguration end-to-end with a real
	// pki.SignerConfig backed by a generated key and self-signed cert.
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

func TestConfigTrustMarksValidation(t *testing.T) {
	validate := validator.New()

	t.Run("valid trust marks pass", func(t *testing.T) {
		cfg := &Config{
			TrustMarks: []TrustMarkConfig{
				{ID: "https://tm.example.com/mark", JWT: "jwt-value"},
			},
		}
		if err := validate.Struct(cfg); err != nil {
			t.Errorf("expected no validation error, got %v", err)
		}
	})

	t.Run("missing trust mark id fails", func(t *testing.T) {
		cfg := &Config{
			TrustMarks: []TrustMarkConfig{
				{JWT: "jwt-value"},
			},
		}
		if err := validate.Struct(cfg); err == nil {
			t.Error("expected validation error for trust mark missing id, got nil")
		}
	})

	t.Run("missing trust mark jwt fails", func(t *testing.T) {
		cfg := &Config{
			TrustMarks: []TrustMarkConfig{
				{ID: "https://tm.example.com/mark"},
			},
		}
		if err := validate.Struct(cfg); err == nil {
			t.Error("expected validation error for trust mark missing jwt, got nil")
		}
	})

	t.Run("empty trust marks slice is valid", func(t *testing.T) {
		cfg := &Config{}
		if err := validate.Struct(cfg); err != nil {
			t.Errorf("expected no validation error for empty trust marks, got %v", err)
		}
	})
}

// writeTestKeyAndCert generates an ephemeral ECDSA P-256 key pair, writes
// the key and a self-signed certificate to temp files, and returns their paths.
func writeTestKeyAndCert(t *testing.T) (keyPath, certPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keyPath = filepath.Join(dir, "key.pem")
	certPath = filepath.Join(dir, "cert.pem")

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		t.Fatal(err)
	}
	return keyPath, certPath
}

func TestBuildEntityConfigurationSignedJWT(t *testing.T) {
	keyPath, certPath := writeTestKeyAndCert(t)

	cfg := &Config{
		Enabled:          true,
		EntityID:         "https://issuer.example.com",
		AuthorityHints:   []string{"https://anchor.example.com"},
		OrganizationName: "Test Org",
		LogoURI:          "https://issuer.example.com/logo.png",
		TTL:              3600,
		TrustMarks: []TrustMarkConfig{
			{ID: "https://tm.example.com/mark", JWT: "tm-jwt-value"},
		},
	}

	keyCfg := &pki.KeyConfig{
		PrivateKeyPath: keyPath,
		ChainPath:      certPath,
	}
	signer := pki.NewSignerConfig(keyCfg)
	svc := NewService(cfg, signer, "https://issuer.example.com")

	metadata := &EntityMetadata{
		OpenIDCredentialIssuer: map[string]any{
			"credential_issuer": "https://issuer.example.com",
		},
	}

	signed, err := svc.BuildEntityConfiguration(metadata)
	if err != nil {
		t.Fatalf("BuildEntityConfiguration failed: %v", err)
	}

	// Parse without verification to inspect claims structure
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified failed: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}

	// iss == sub == entity_id
	if claims["iss"] != "https://issuer.example.com" {
		t.Errorf("iss = %v, want https://issuer.example.com", claims["iss"])
	}
	if claims["sub"] != "https://issuer.example.com" {
		t.Errorf("sub = %v, want https://issuer.example.com", claims["sub"])
	}

	// authority_hints
	hints, ok := claims["authority_hints"].([]any)
	if !ok || len(hints) != 1 || hints[0] != "https://anchor.example.com" {
		t.Errorf("authority_hints = %v, want [https://anchor.example.com]", claims["authority_hints"])
	}

	// metadata.openid_credential_issuer
	meta, ok := claims["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing")
	}
	if _, ok := meta["openid_credential_issuer"]; !ok {
		t.Error("openid_credential_issuer missing from metadata")
	}
	// federation_entity injected from config
	fedEntity, ok := meta["federation_entity"].(map[string]any)
	if !ok {
		t.Fatal("federation_entity missing from metadata")
	}
	if fedEntity["organization_name"] != "Test Org" {
		t.Errorf("organization_name = %v, want Test Org", fedEntity["organization_name"])
	}

	// jwks present
	if claims["jwks"] == nil {
		t.Error("jwks missing")
	}

	// trust_marks
	tms, ok := claims["trust_marks"].([]any)
	if !ok || len(tms) != 1 {
		t.Errorf("trust_marks = %v, want 1 entry", claims["trust_marks"])
	}

	// exp and iat present
	if claims["exp"] == nil {
		t.Error("exp missing")
	}
	if claims["iat"] == nil {
		t.Error("iat missing")
	}
}

// TestBuildEntityConfigurationDoesNotMutateInput guards against
// BuildEntityConfiguration mutating the caller-supplied *EntityMetadata (or
// the maps it holds) when it injects federation_entity fields. A caller
// that reuses the same *EntityMetadata across requests must not see fields
// injected for one request "leak" into another.
func TestBuildEntityConfigurationDoesNotMutateInput(t *testing.T) {
	keyPath, certPath := writeTestKeyAndCert(t)
	keyCfg := &pki.KeyConfig{PrivateKeyPath: keyPath, ChainPath: certPath}
	signer := pki.NewSignerConfig(keyCfg)

	metadata := &EntityMetadata{
		OpenIDCredentialIssuer: map[string]any{
			"credential_issuer": "https://issuer.example.com",
		},
	}

	cfg1 := &Config{
		Enabled:          true,
		EntityID:         "https://issuer.example.com",
		OrganizationName: "Test Org",
		LogoURI:          "https://issuer.example.com/logo.png",
	}
	svc1 := NewService(cfg1, signer, "https://issuer.example.com")

	if _, err := svc1.BuildEntityConfiguration(metadata); err != nil {
		t.Fatalf("BuildEntityConfiguration failed: %v", err)
	}

	// The caller's original metadata must be unaffected: no federation_entity
	// map should have been injected into it, and its own map must be intact.
	if metadata.FederationEntity != nil {
		t.Errorf("expected caller's metadata.FederationEntity to remain nil, got %v", metadata.FederationEntity)
	}
	if len(metadata.OpenIDCredentialIssuer) != 1 {
		t.Errorf("expected caller's OpenIDCredentialIssuer to be untouched, got %v", metadata.OpenIDCredentialIssuer)
	}

	// Reuse the same metadata instance with a second, differently-configured
	// service/request and make sure nothing from the first call is visible
	// afterwards, and that the two signed configurations don't cross-pollute.
	cfg2 := &Config{
		Enabled:          true,
		EntityID:         "https://issuer2.example.com",
		OrganizationName: "Other Org",
	}
	svc2 := NewService(cfg2, signer, "https://issuer2.example.com")

	signed2, err := svc2.BuildEntityConfiguration(metadata)
	if err != nil {
		t.Fatalf("second BuildEntityConfiguration failed: %v", err)
	}

	if metadata.FederationEntity != nil {
		t.Errorf("expected caller's metadata.FederationEntity to remain nil after second call, got %v", metadata.FederationEntity)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(signed2, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified failed: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	meta, ok := claims["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing")
	}
	fedEntity, ok := meta["federation_entity"].(map[string]any)
	if !ok {
		t.Fatal("federation_entity missing from second signed configuration")
	}
	if fedEntity["organization_name"] != "Other Org" {
		t.Errorf("organization_name = %v, want Other Org", fedEntity["organization_name"])
	}
	if _, ok := fedEntity["logo_uri"]; ok {
		t.Errorf("expected no logo_uri (cfg2 has none), but got %v -- possible cross-request contamination", fedEntity["logo_uri"])
	}
}
