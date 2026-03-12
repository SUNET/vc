package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

// mockVC20KeyResolver is a simple mock for testing
type mockVC20KeyResolver struct {
	key crypto.PublicKey
	err error
}

func (m *mockVC20KeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}

func TestNewVC20Handler(t *testing.T) {
	tests := []struct {
		name    string
		opts    []VC20HandlerOption
		wantErr bool
	}{
		{
			name: "empty options",
			opts: nil,
		},
		{
			name: "with static key",
			opts: []VC20HandlerOption{
				WithVC20StaticKey(&ecdsa.PublicKey{}),
			},
		},
		{
			name: "with trusted issuers",
			opts: []VC20HandlerOption{
				WithVC20TrustedIssuers([]string{"https://issuer.example.com"}),
			},
		},
		{
			name: "with clock",
			opts: []VC20HandlerOption{
				WithVC20Clock(func() time.Time { return time.Now() }),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewVC20Handler(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewVC20Handler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && h == nil {
				t.Error("NewVC20Handler() returned nil handler")
			}
		})
	}
}

func TestVC20Handler_VerifyAndExtract_EmptyToken(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	_, err = h.VerifyAndExtract(t.Context(), "")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestVC20Handler_VerifyAndExtract_InvalidJSON(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	h, err := NewVC20Handler(
		WithVC20StaticKey(&privKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	_, err = h.VerifyAndExtract(t.Context(), "not-json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestVC20Handler_VerifyAndExtract_MissingIssuer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	h, err := NewVC20Handler(
		WithVC20StaticKey(&privKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	cred := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		// No issuer
	}
	credJSON, _ := json.Marshal(cred)

	_, err = h.VerifyAndExtract(t.Context(), string(credJSON))
	if err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestVC20Handler_VerifyAndExtract_UntrustedIssuer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	h, err := NewVC20Handler(
		WithVC20StaticKey(&privKey.PublicKey),
		WithVC20TrustedIssuers([]string{"https://trusted.example.com"}),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	cred := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "https://untrusted.example.com",
	}
	credJSON, _ := json.Marshal(cred)

	_, err = h.VerifyAndExtract(t.Context(), string(credJSON))
	if err == nil {
		t.Error("expected error for untrusted issuer")
	}
}

func TestVC20Handler_VerifyAndExtract_MissingProof(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	h, err := NewVC20Handler(
		WithVC20StaticKey(&privKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	cred := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "https://issuer.example.com",
		// No proof
	}
	credJSON, _ := json.Marshal(cred)

	_, err = h.VerifyAndExtract(t.Context(), string(credJSON))
	if err == nil {
		t.Error("expected error for missing proof")
	}
}

func TestVC20Handler_VerifyAndExtract_MissingKeyResolver(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	cred := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "https://issuer.example.com",
		"proof": map[string]any{
			"type":               "DataIntegrityProof",
			"cryptosuite":        "ecdsa-rdfc-2019",
			"verificationMethod": "did:key:z123",
			"proofPurpose":       "assertionMethod",
		},
	}
	credJSON, _ := json.Marshal(cred)

	_, err = h.VerifyAndExtract(t.Context(), string(credJSON))
	if err == nil {
		t.Error("expected error for missing key resolver")
	}
}

func TestVC20Handler_extractIssuer(t *testing.T) {
	h, _ := NewVC20Handler()

	tests := []struct {
		name    string
		cred    map[string]any
		want    string
		wantErr bool
	}{
		{
			name:    "string issuer",
			cred:    map[string]any{"issuer": "https://issuer.example.com"},
			want:    "https://issuer.example.com",
			wantErr: false,
		},
		{
			name:    "object issuer with id",
			cred:    map[string]any{"issuer": map[string]any{"id": "https://issuer.example.com", "name": "Test Issuer"}},
			want:    "https://issuer.example.com",
			wantErr: false,
		},
		{
			name:    "missing issuer",
			cred:    map[string]any{},
			want:    "",
			wantErr: true,
		},
		{
			name:    "object issuer without id",
			cred:    map[string]any{"issuer": map[string]any{"name": "Test Issuer"}},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.extractIssuer(tt.cred)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractIssuer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVC20Handler_decodeVPToken(t *testing.T) {
	h, _ := NewVC20Handler()

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "plain JSON",
			token:   `{"type": "VerifiableCredential"}`,
			wantErr: false,
		},
		{
			name:    "JSON with whitespace",
			token:   `  {"type": "VerifiableCredential"}  `,
			wantErr: false,
		},
		// Base64 encoded tokens handled by decodeVPToken
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.decodeVPToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeVPToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Error("decodeVPToken() returned empty bytes")
			}
		})
	}
}

func TestVC20VerificationResult_GetClaims(t *testing.T) {
	result := &VC20VerificationResult{
		Claims: map[string]any{
			"foo": "bar",
		},
		CredentialSubject: map[string]any{
			"name": "Test User",
		},
	}

	claims := result.GetClaims()
	if claims["foo"] != "bar" {
		t.Errorf("GetClaims() foo = %v, want bar", claims["foo"])
	}

	subject := result.GetCredentialSubject()
	if subject["name"] != "Test User" {
		t.Errorf("GetCredentialSubject() name = %v, want Test User", subject["name"])
	}
}

func TestStaticVC20KeyResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resolver := &StaticVC20KeyResolver{Key: &privKey.PublicKey}

	key, err := resolver.ResolveKey(t.Context(), "any-method")
	if err != nil {
		t.Fatalf("ResolveKey() error = %v", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA key, got %T", key)
	}

	if ecdsaKey.X.Cmp(privKey.PublicKey.X) != 0 || ecdsaKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("resolved key does not match original")
	}
}

func TestStaticVC20KeyResolver_NoKey(t *testing.T) {
	resolver := &StaticVC20KeyResolver{}

	_, err := resolver.ResolveKey(t.Context(), "any-method")
	if err == nil {
		t.Error("expected error for nil key")
	}
}

// Tests for CreateCredential (signing) functionality

func TestCreateCredential_NoSignerConfig(t *testing.T) {
	handler, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	_, err = handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id":   "did:example:subject",
			"name": "Test User",
		},
	})
	if err == nil {
		t.Error("expected error when signer config not set")
	}
}

func TestCreateCredential_ECDSA2019(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteECDSA2019,
		}),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	result, err := handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id":     "did:example:subject",
			"degree": "Bachelor of Science",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	if result.Issuer != "did:example:issuer" {
		t.Errorf("Issuer = %v, want did:example:issuer", result.Issuer)
	}

	// Verify the credential structure
	var cred map[string]any
	if err := json.Unmarshal(result.CredentialJSON, &cred); err != nil {
		t.Fatalf("failed to unmarshal credential: %v", err)
	}

	// Check proof exists
	proof, ok := cred["proof"].(map[string]any)
	if !ok {
		t.Fatal("credential missing proof")
	}
	if proof["cryptosuite"] != CryptosuiteECDSA2019 {
		t.Errorf("cryptosuite = %v, want %s", proof["cryptosuite"], CryptosuiteECDSA2019)
	}
}

func TestCreateCredential_InvalidKeyType(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteEdDSA2022, // EdDSA suite but ECDSA key
		}),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	_, err = handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id": "did:example:subject",
		},
	})
	if err == nil {
		t.Error("expected error for wrong key type")
	}
}

func TestCreateCredential_WithExpiration(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteECDSA2019,
		}),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	expiration := time.Now().Add(24 * time.Hour)
	result, err := handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id": "did:example:subject",
		},
		ValidUntil: &expiration,
	})
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	var cred map[string]any
	if err := json.Unmarshal(result.CredentialJSON, &cred); err != nil {
		t.Fatalf("failed to unmarshal credential: %v", err)
	}

	if _, ok := cred["validUntil"]; !ok {
		t.Error("credential missing validUntil")
	}
}

func TestCreateCredential_RoundTrip(t *testing.T) {
	// Test that a created credential can be verified
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteECDSA2019,
		}),
		WithVC20StaticKey(&privKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Create credential
	createResult, err := handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id":     "did:example:subject",
			"degree": "Master of Science",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	// Verify credential
	verifyResult, err := handler.VerifyAndExtract(t.Context(), string(createResult.CredentialJSON))
	if err != nil {
		t.Fatalf("VerifyAndExtract() error = %v", err)
	}

	if verifyResult.Issuer != "did:example:issuer" {
		t.Errorf("verified issuer = %v, want did:example:issuer", verifyResult.Issuer)
	}
	if verifyResult.Subject != "did:example:subject" {
		t.Errorf("verified subject = %v, want did:example:subject", verifyResult.Subject)
	}
	if verifyResult.CredentialSubject["degree"] != "Master of Science" {
		t.Errorf("verified degree = %v, want Master of Science", verifyResult.CredentialSubject["degree"])
	}
}

func TestCreateCredential_EdDSA2022(t *testing.T) {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteEdDSA2022,
		}),
		WithVC20StaticKey(pubKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Create credential
	createResult, err := handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id":     "did:example:subject",
			"degree": "Master of Science",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	// Verify credential
	verifyResult, err := handler.VerifyAndExtract(t.Context(), string(createResult.CredentialJSON))
	if err != nil {
		t.Fatalf("VerifyAndExtract() error = %v", err)
	}

	if verifyResult.Issuer != "did:example:issuer" {
		t.Errorf("verified issuer = %v, want did:example:issuer", verifyResult.Issuer)
	}
	if verifyResult.Subject != "did:example:subject" {
		t.Errorf("verified subject = %v, want did:example:subject", verifyResult.Subject)
	}
}

func TestCreateCredential_ECDSASd2023(t *testing.T) {
	// Generate ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	handler, err := NewVC20Handler(
		WithVC20SignerConfig(&VC20SignerConfig{
			PrivateKey:         privKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        CryptosuiteECDSASd,
		}),
		WithVC20StaticKey(&privKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Create credential
	createResult, err := handler.CreateCredential(t.Context(), &VC20CreateRequest{
		Types: []string{"UniversityDegreeCredential"},
		Subject: map[string]any{
			"id":     "did:example:subject",
			"degree": "Bachelor of Science",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	// Verify credential - SD credentials return compact JSON
	verifyResult, err := handler.VerifyAndExtract(t.Context(), string(createResult.CredentialJSON))
	if err != nil {
		t.Fatalf("VerifyAndExtract() error = %v", err)
	}

	if verifyResult.Issuer != "did:example:issuer" {
		t.Errorf("verified issuer = %v, want did:example:issuer", verifyResult.Issuer)
	}
	if verifyResult.Subject != "did:example:subject" {
		t.Errorf("verified subject = %v, want did:example:subject", verifyResult.Subject)
	}
}

// TestWithVC20KeyResolver tests that the WithVC20KeyResolver option correctly sets up the handler.
func TestWithVC20KeyResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a custom key resolver
	resolver := &mockVC20KeyResolver{key: &privKey.PublicKey}

	h, err := NewVC20Handler(
		WithVC20KeyResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Verify the key resolver was set correctly
	if h.keyResolver != resolver {
		t.Error("expected keyResolver to be set to custom resolver")
	}
}

// TestWithVC20RevocationCheck tests the revocation check option.
func TestWithVC20RevocationCheck(t *testing.T) {
	tests := []struct {
		name          string
		enableCheck   bool
		expectedCheck bool
	}{
		{
			name:          "revocation check enabled",
			enableCheck:   true,
			expectedCheck: true,
		},
		{
			name:          "revocation check disabled",
			enableCheck:   false,
			expectedCheck: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewVC20Handler(
				WithVC20RevocationCheck(tt.enableCheck),
			)
			if err != nil {
				t.Fatalf("NewVC20Handler() error = %v", err)
			}

			if h.checkRevocation != tt.expectedCheck {
				t.Errorf("checkRevocation = %v, want %v", h.checkRevocation, tt.expectedCheck)
			}
		})
	}
}

// TestWithVC20AllowedSkew tests the allowed skew option.
func TestWithVC20AllowedSkew(t *testing.T) {
	skew := 10 * time.Minute

	h, err := NewVC20Handler(
		WithVC20AllowedSkew(skew),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	if h.allowedSkew != skew {
		t.Errorf("allowedSkew = %v, want %v", h.allowedSkew, skew)
	}
}

// TestVC20Handler_KeyResolverError tests handling of key resolver errors.
func TestVC20Handler_KeyResolverError(t *testing.T) {
	// Create a resolver that returns an error
	resolver := &mockVC20KeyResolver{
		err: context.DeadlineExceeded,
	}

	h, err := NewVC20Handler(
		WithVC20KeyResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Create a valid credential structure that needs key resolution
	cred := map[string]any{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"proof": map[string]any{
			"type":               "DataIntegrityProof",
			"cryptosuite":        "ecdsa-rdfc-2019",
			"verificationMethod": "did:key:z123",
			"proofPurpose":       "assertionMethod",
			"proofValue":         "some-proof-value",
			"created":            "2024-01-01T00:00:00Z",
		},
	}
	credJSON, _ := json.Marshal(cred)

	_, err = h.VerifyAndExtract(t.Context(), string(credJSON))
	if err == nil {
		t.Error("expected error when key resolver fails")
	}
}

// TestVC20Handler_AllOptionsComposed tests that all options can be composed together.
func TestVC20Handler_AllOptionsComposed(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	customClock := func() time.Time {
		return time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	}

	h, err := NewVC20Handler(
		WithVC20StaticKey(&privKey.PublicKey),
		WithVC20TrustedIssuers([]string{"https://issuer1.example.com", "https://issuer2.example.com"}),
		WithVC20RevocationCheck(true),
		WithVC20Clock(customClock),
		WithVC20AllowedSkew(15*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	// Verify all options were applied
	if h.keyResolver == nil {
		t.Error("expected keyResolver to be set")
	}
	if !h.trustedIssuers["https://issuer1.example.com"] {
		t.Error("expected issuer1 to be trusted")
	}
	if !h.trustedIssuers["https://issuer2.example.com"] {
		t.Error("expected issuer2 to be trusted")
	}
	if !h.checkRevocation {
		t.Error("expected checkRevocation to be true")
	}
	if h.clock() != customClock() {
		t.Error("expected custom clock to be set")
	}
	if h.allowedSkew != 15*time.Minute {
		t.Errorf("allowedSkew = %v, want 15m", h.allowedSkew)
	}
}

// TestVC20Handler_DecodeVPToken_Base64Variants tests base64 decoding of VP tokens.
func TestVC20Handler_DecodeVPToken_Base64Variants(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "plain JSON object",
			input:   `{"@context": "https://www.w3.org/ns/credentials/v2"}`,
			wantErr: false,
		},
		{
			name:    "plain JSON array",
			input:   `[{"@context": "https://www.w3.org/ns/credentials/v2"}]`,
			wantErr: false,
		},
		{
			name:    "JSON with whitespace",
			input:   "  \n  {\"test\": \"value\"}  ",
			wantErr: false,
		},
		{
			name:    "invalid base64 - not decodable",
			input:   "not-valid-base64-!!!@@@",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.decodeVPToken(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeVPToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVC20Handler_ExtractCredentialFromVP_EdgeCases tests edge cases for VP credential extraction.
func TestVC20Handler_ExtractCredentialFromVP_EdgeCases(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	tests := []struct {
		name    string
		vp      map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing verifiableCredential",
			vp:      map[string]any{"@context": "https://www.w3.org/ns/credentials/v2"},
			wantErr: true,
			errMsg:  "VP missing verifiableCredential",
		},
		{
			name:    "empty verifiableCredential array",
			vp:      map[string]any{"verifiableCredential": []any{}},
			wantErr: true,
			errMsg:  "VP verifiableCredential array is empty",
		},
		{
			name: "verifiableCredential array with invalid element",
			vp: map[string]any{
				"verifiableCredential": []any{"not-a-map"},
			},
			wantErr: true,
			errMsg:  "VP verifiableCredential is not a valid credential object",
		},
		{
			name: "verifiableCredential unexpected type (string)",
			vp: map[string]any{
				"verifiableCredential": "invalid-type",
			},
			wantErr: true,
			errMsg:  "VP verifiableCredential has unexpected type",
		},
		{
			name: "valid single credential",
			vp: map[string]any{
				"verifiableCredential": map[string]any{
					"@context": []string{"https://www.w3.org/ns/credentials/v2"},
					"type":     []string{"VerifiableCredential"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid credential array",
			vp: map[string]any{
				"verifiableCredential": []any{
					map[string]any{
						"@context": []string{"https://www.w3.org/ns/credentials/v2"},
						"type":     []string{"VerifiableCredential"},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := h.extractCredentialFromVP(tt.vp)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractCredentialFromVP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("extractCredentialFromVP() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestVC20Handler_ExtractProof_EdgeCases tests edge cases for proof extraction.
func TestVC20Handler_ExtractProof_EdgeCases(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	tests := []struct {
		name    string
		cred    map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing proof",
			cred:    map[string]any{"@context": "https://www.w3.org/ns/credentials/v2"},
			wantErr: true,
			errMsg:  "credential missing proof",
		},
		{
			name: "empty proof array",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"proof":    []any{},
			},
			wantErr: true,
			errMsg:  "credential proof array is empty",
		},
		{
			name: "proof with unexpected type",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"proof":    "invalid-proof-type",
			},
			wantErr: true,
			errMsg:  "proof has unexpected type",
		},
		{
			name: "valid single proof",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"proof": map[string]any{
					"type":         "DataIntegrityProof",
					"cryptosuite":  "ecdsa-rdfc-2019",
					"proofPurpose": "assertionMethod",
				},
			},
			wantErr: false,
		},
		{
			name: "valid proof array (takes first)",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"proof": []any{
					map[string]any{
						"type":         "DataIntegrityProof",
						"cryptosuite":  "ecdsa-rdfc-2019",
						"proofPurpose": "assertionMethod",
					},
					map[string]any{
						"type":         "DataIntegrityProof",
						"cryptosuite":  "eddsa-rdfc-2022",
						"proofPurpose": "assertionMethod",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := h.extractProof(tt.cred)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractProof() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("extractProof() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
			if !tt.wantErr && proof == nil {
				t.Error("expected non-nil proof")
			}
		})
	}
}

// TestVC20Handler_ExtractIssuer_EdgeCases tests issuer extraction from various formats.
func TestVC20Handler_ExtractIssuer_EdgeCases(t *testing.T) {
	h, err := NewVC20Handler()
	if err != nil {
		t.Fatalf("NewVC20Handler() error = %v", err)
	}

	tests := []struct {
		name      string
		cred      map[string]any
		wantErr   bool
		wantValue string
	}{
		{
			name:    "missing issuer",
			cred:    map[string]any{"@context": "https://www.w3.org/ns/credentials/v2"},
			wantErr: true,
		},
		{
			name: "issuer as string",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"issuer":   "did:example:issuer",
			},
			wantErr:   false,
			wantValue: "did:example:issuer",
		},
		{
			name: "issuer as object with id",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"issuer": map[string]any{
					"id":   "did:example:issuer",
					"name": "Example Issuer",
				},
			},
			wantErr:   false,
			wantValue: "did:example:issuer",
		},
		{
			name: "issuer as object without id",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"issuer": map[string]any{
					"name": "Example Issuer",
				},
			},
			wantErr: true,
		},
		{
			name: "issuer with unexpected type",
			cred: map[string]any{
				"@context": "https://www.w3.org/ns/credentials/v2",
				"issuer":   12345, // invalid type
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.extractIssuer(tt.cred)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result != tt.wantValue {
				t.Errorf("extractIssuer() = %v, want %v", result, tt.wantValue)
			}
		})
	}
}

// contains is a helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
