package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

func TestNewSDJWTHandler(t *testing.T) {
	h, err := NewSDJWTHandler()
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}
	if h == nil {
		t.Fatal("NewSDJWTHandler() returned nil")
	}
	if h.client == nil {
		t.Error("client should not be nil")
	}
	if h.verifyOpts == nil {
		t.Error("verifyOpts should not be nil")
	}
}

func TestNewSDJWTHandler_WithOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	trustedIssuers := []string{"https://issuer.example.com"}

	h, err := NewSDJWTHandler(
		WithSDJWTStaticKey(&privateKey.PublicKey),
		WithSDJWTTrustedIssuers(trustedIssuers),
	)
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}

	if h.keyResolver == nil {
		t.Error("keyResolver should be set")
	}

	if len(h.trustedIssuers) != 1 {
		t.Errorf("trustedIssuers = %d, want 1", len(h.trustedIssuers))
	}
}

func TestNewSDJWTHandler_WithKeyBinding(t *testing.T) {
	h, err := NewSDJWTHandler(
		WithSDJWTRequireKeyBinding("test-nonce", "https://verifier.example.com"),
	)
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}

	if !h.verifyOpts.RequireKeyBinding {
		t.Error("RequireKeyBinding should be true")
	}
	if h.verifyOpts.ExpectedNonce != "test-nonce" {
		t.Errorf("ExpectedNonce = %s, want test-nonce", h.verifyOpts.ExpectedNonce)
	}
	if h.verifyOpts.ExpectedAudience != "https://verifier.example.com" {
		t.Errorf("ExpectedAudience = %s", h.verifyOpts.ExpectedAudience)
	}
}

func TestIsSDJWTFormat(t *testing.T) {
	tests := []struct {
		name    string
		vpToken string
		want    bool
	}{
		{ // #nosec G101
			name:    "Plain JWT",
			vpToken: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			want:    true,
		},
		{ // #nosec G101
			name:    "SD-JWT with disclosure",
			vpToken: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature~WyJzYWx0IiwiY2xhaW0iLCJ2YWx1ZSJd~",
			want:    true,
		},
		{ // #nosec G101
			name:    "SD-JWT with KB-JWT",
			vpToken: "eyJhbGciOiJFUzI1NiJ9.payload.sig~disclosure~eyJhbGciOiJFUzI1NiJ9.kbpayload.kbsig",
			want:    true,
		},
		{
			name:    "Empty string",
			vpToken: "",
			want:    false,
		},
		{
			name:    "Invalid format",
			vpToken: "not-a-jwt",
			want:    false,
		},
		{
			name:    "Only one dot",
			vpToken: "header.payload",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSDJWTFormat(tt.vpToken)
			if got != tt.want {
				t.Errorf("IsSDJWTFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractSDJWTClaims_Empty(t *testing.T) {
	_, err := ExtractSDJWTClaims("")
	if err == nil {
		t.Error("ExtractSDJWTClaims() should fail for empty token")
	}
}

func TestSDJWTHandler_VerifyAndExtract_EmptyToken(t *testing.T) {
	h, _ := NewSDJWTHandler()

	_, err := h.VerifyAndExtract(t.Context(), "")
	if err == nil {
		t.Error("VerifyAndExtract() should fail for empty token")
	}
}

func TestSDJWTHandler_VerifyAndExtract_NoKeyResolver(t *testing.T) {
	h, _ := NewSDJWTHandler()

	// Create a minimal valid-looking SD-JWT
	// This will fail at key resolution
	token := createTestSDJWT(t)

	_, err := h.VerifyAndExtract(t.Context(), token)
	if err == nil {
		t.Error("VerifyAndExtract() should fail without key resolver")
	}
}

func TestSDJWTHandler_VerifyAndExtract_UntrustedIssuer(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	h, _ := NewSDJWTHandler(
		WithSDJWTStaticKey(&privateKey.PublicKey),
		WithSDJWTTrustedIssuers([]string{"https://other-issuer.example.com"}),
	)

	// Create SD-JWT with different issuer
	token := createTestSDJWT(t)

	_, err := h.VerifyAndExtract(t.Context(), token)
	if err == nil {
		t.Error("VerifyAndExtract() should fail for untrusted issuer")
	}
}

func TestSDJWTVerificationResult_GetClaims(t *testing.T) {
	result := &SDJWTVerificationResult{
		Valid:  true,
		Issuer: "https://issuer.example.com",
		Claims: map[string]any{
			"iss":         "https://issuer.example.com",
			"sub":         "user123",
			"family_name": "Doe",
		},
		DisclosedClaims: map[string]any{
			"family_name": "Doe",
		},
	}

	claims := result.GetClaims()
	if claims["family_name"] != "Doe" {
		t.Error("GetClaims() should return all claims")
	}

	disclosed := result.GetDisclosedClaims()
	if disclosed["family_name"] != "Doe" {
		t.Error("GetDisclosedClaims() should return disclosed claims")
	}
}

func TestMapSDJWTToOIDC(t *testing.T) {
	sdJWTClaims := map[string]any{
		"family_name":  "Doe",
		"given_name":   "John",
		"birth_date":   "1990-01-15",
		"age_over_18":  true,
		"custom_claim": "custom_value",
		"_sd":          []string{"hash1", "hash2"}, // Should be filtered
		"_sd_alg":      "sha-256",                  // Should be filtered
	}

	oidcClaims := MapSDJWTToOIDC(sdJWTClaims)

	// Check standard mappings
	if oidcClaims["family_name"] != "Doe" {
		t.Error("family_name should be mapped")
	}
	if oidcClaims["birthdate"] != "1990-01-15" {
		t.Error("birth_date should be mapped to birthdate")
	}
	if oidcClaims["age_over_18"] != true {
		t.Error("age_over_18 should be passed through")
	}

	// Custom claims should pass through
	if oidcClaims["custom_claim"] != "custom_value" {
		t.Error("custom_claim should pass through")
	}

	// Internal claims should be filtered
	if _, ok := oidcClaims["_sd"]; ok {
		t.Error("_sd should be filtered")
	}
	if _, ok := oidcClaims["_sd_alg"]; ok {
		t.Error("_sd_alg should be filtered")
	}
}

func TestStaticKeyResolver(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := &StaticKeyResolver{Key: &privateKey.PublicKey}

	key, err := resolver.ResolveKey(t.Context(), "any-issuer", "any-kid")
	if err != nil {
		t.Fatalf("ResolveKey() error = %v", err)
	}
	if key != &privateKey.PublicKey {
		t.Error("ResolveKey() should return the static key")
	}
}

func TestStaticKeyResolver_NilKey(t *testing.T) {
	resolver := &StaticKeyResolver{}

	_, err := resolver.ResolveKey(t.Context(), "any-issuer", "any-kid")
	if err == nil {
		t.Error("ResolveKey() should fail with nil key")
	}
}

func TestIsInternalSDJWTClaim(t *testing.T) {
	tests := []struct {
		claim    string
		internal bool
	}{
		{"_sd", true},
		{"_sd_alg", true},
		{"cnf", true},
		{"vct", true},
		{"status", true},
		{"family_name", false},
		{"given_name", false},
		{"iss", false},
		{"sub", false},
	}

	for _, tt := range tests {
		got := isInternalSDJWTClaim(tt.claim)
		if got != tt.internal {
			t.Errorf("isInternalSDJWTClaim(%s) = %v, want %v", tt.claim, got, tt.internal)
		}
	}
}

func TestGetStringClaim(t *testing.T) {
	claims := map[string]any{
		"str":    "string_value",
		"number": 42,
		"bool":   true,
	}

	if getStringClaim(claims, "str") != "string_value" {
		t.Error("should return string value")
	}
	if getStringClaim(claims, "number") != "" {
		t.Error("should return empty for non-string")
	}
	if getStringClaim(claims, "missing") != "" {
		t.Error("should return empty for missing")
	}
}

func TestSDJWTHandler_WithVerificationOptions(t *testing.T) {
	opts := &sdjwtvc.VerificationOptions{
		ValidateTime:     false,
		AllowedClockSkew: 10 * time.Minute,
	}

	h, err := NewSDJWTHandler(WithSDJWTVerificationOptions(opts))
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}

	if h.verifyOpts.ValidateTime != false {
		t.Error("ValidateTime should be false")
	}
	if h.verifyOpts.AllowedClockSkew != 10*time.Minute {
		t.Error("AllowedClockSkew should be 10 minutes")
	}
}

// MockKeyResolver is a mock implementation for testing
type MockKeyResolver struct {
	Key crypto.PublicKey
	Err error
}

func (r *MockKeyResolver) ResolveKey(ctx context.Context, issuer string, keyID string) (crypto.PublicKey, error) {
	return r.Key, r.Err
}

func TestSDJWTHandler_WithKeyResolver(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := &MockKeyResolver{Key: &privateKey.PublicKey}

	h, err := NewSDJWTHandler(WithSDJWTKeyResolver(resolver))
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}

	if h.keyResolver != resolver {
		t.Error("keyResolver should be set to mock resolver")
	}
}

// testSigner implements sdjwtvc.Signer for unit tests.
type testSigner struct {
	key    any
	algo   string
	kid    string
	pubKey any
	method jwt.SigningMethod
}

func newTestSigner(key *ecdsa.PrivateKey, kid string) *testSigner {
	method, algo := jose.GetSigningMethodFromKey(key)
	return &testSigner{key: key, algo: algo, kid: kid, pubKey: &key.PublicKey, method: method}
}

func (s *testSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.method.Sign(string(data), s.key)
}
func (s *testSigner) Algorithm() string { return s.algo }
func (s *testSigner) KeyID() string     { return s.kid }
func (s *testSigner) PublicKey() any    { return s.pubKey }

// marshalVCTM marshals a VCTM to JSON bytes and computes the SRI integrity hash.
func marshalVCTM(t *testing.T, vctm *sdjwtvc.VCTM) (raw []byte, integrity string) {
	t.Helper()
	raw, err := json.Marshal(vctm)
	if err != nil {
		t.Fatalf("Failed to marshal VCTM: %v", err)
	}
	integrity, err = vctm.SRIIntegrity(raw)
	if err != nil {
		t.Fatalf("Failed to compute integrity: %v", err)
	}
	return raw, integrity
}

// createTestSDJWT creates a minimal test SD-JWT for testing
func createTestSDJWT(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	client := sdjwtvc.New()

	documentData := []byte(`{
		"family_name": "Doe",
		"given_name": "John"
	}`)

	vctm := &sdjwtvc.VCTM{
		VCT:  "https://example.com/credentials/test",
		Name: "Test Credential",
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "key-1")

	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		documentData,
		nil, // no holder binding
		&sdjwtvc.CredentialOptions{Integrity: integrity},
	)
	if err != nil {
		t.Fatalf("Failed to build SD-JWT: %v", err)
	}

	return token
}

func TestSDJWTHandler_VerifyAndExtract_Valid(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create the handler with the matching public key
	h, err := NewSDJWTHandler(
		WithSDJWTStaticKey(&privateKey.PublicKey),
		WithSDJWTTrustedIssuers([]string{"https://issuer.example.com"}),
	)
	if err != nil {
		t.Fatalf("NewSDJWTHandler() error = %v", err)
	}

	// Create a valid SD-JWT with the same private key
	client := sdjwtvc.New()

	documentData := []byte(`{
		"family_name": "Doe",
		"given_name": "John"
	}`)

	vctm := &sdjwtvc.VCTM{
		VCT:  "https://example.com/credentials/test",
		Name: "Test Credential",
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "key-1")

	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		documentData,
		nil, // no holder binding
		&sdjwtvc.CredentialOptions{Integrity: integrity},
	)
	if err != nil {
		t.Fatalf("Failed to build SD-JWT: %v", err)
	}

	// Verify and extract
	result, err := h.VerifyAndExtract(t.Context(), token)
	if err != nil {
		t.Fatalf("VerifyAndExtract() error = %v", err)
	}

	if !result.Valid {
		t.Error("result should be valid")
	}
	if result.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %s, want https://issuer.example.com", result.Issuer)
	}

	// Claims are in the main Claims map (not DisclosedClaims since not selectively disclosed)
	claims := result.GetClaims()
	if claims["family_name"] != "Doe" {
		t.Errorf("family_name = %v, want Doe", claims["family_name"])
	}
	if claims["given_name"] != "John" {
		t.Errorf("given_name = %v, want John", claims["given_name"])
	}

	// Check expiration time (nbf is set, iat might not be set by BuildCredential)
	if result.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
}
