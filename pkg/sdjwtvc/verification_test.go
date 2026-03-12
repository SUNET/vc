package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAndVerify_ValidCredential(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.Y.Bytes()),
	}

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	documentData := []byte(`{"test_claim": "test_value"}`)

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw, documentData, holderJWK,
		&CredentialOptions{Integrity: integrity},
	)
	require.NoError(t, err)

	result, err := client.ParseAndVerify(sdJWT, &issuerPrivateKey.PublicKey, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)

	assert.Equal(t, "dc+sd-jwt", result.Header["typ"])
	assert.Equal(t, "ES256", result.Header["alg"])

	assert.Equal(t, "https://issuer.example.com", result.Claims["iss"])
	assert.Equal(t, "TestCredential", result.Claims["vct"])

	assert.Greater(t, len(result.Disclosures), 0)
	assert.NotNil(t, result.DisclosedClaims["test_claim"])
}

func TestParseAndVerify_InvalidSignature(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{Integrity: integrity},
	)
	require.NoError(t, err)

	wrongPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	result, err := client.ParseAndVerify(sdJWT, &wrongPrivateKey.PublicKey, nil)
	assert.Error(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestParseAndVerify_ExpiredCredential(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{
			ExpirationDays: -1,
			Integrity:      integrity,
		},
	)
	require.NoError(t, err)

	result, err := client.ParseAndVerify(sdJWT, &issuerPrivateKey.PublicKey, &VerificationOptions{
		ValidateTime: true,
	})
	assert.Error(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, err.Error(), "expired")
}

func TestParseAndVerify_SkipTimeValidation(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{
			ExpirationDays: -1,
			Integrity:      integrity,
		},
	)
	require.NoError(t, err)

	result, err := client.ParseAndVerify(sdJWT, &issuerPrivateKey.PublicKey, &VerificationOptions{
		ValidateTime: false,
	})
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestParseAndVerify_WithKeyBinding(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.Y.Bytes()),
	}

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)
	require.NoError(t, err)

	nonce := "test-nonce-12345"
	audience := "https://verifier.example.com"
	kbJWT, err := CreateKeyBindingJWT(sdJWT, nonce, audience, holderPrivateKey, "sha-256")
	require.NoError(t, err)

	combined := sdJWT + kbJWT

	result, err := client.ParseAndVerify(combined, &issuerPrivateKey.PublicKey, &VerificationOptions{
		ExpectedNonce:    nonce,
		ExpectedAudience: audience,
	})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.KeyBindingValid)
	assert.NotNil(t, result.KeyBindingClaims)
	assert.Equal(t, nonce, result.KeyBindingClaims["nonce"])
	assert.Equal(t, audience, result.KeyBindingClaims["aud"])
}

func TestParseAndVerify_KeyBindingRequired(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{Integrity: integrity},
	)
	require.NoError(t, err)

	result, err := client.ParseAndVerify(sdJWT, &issuerPrivateKey.PublicKey, &VerificationOptions{
		RequireKeyBinding: true,
	})
	assert.Error(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, err.Error(), "key binding JWT required")
}

func TestParseAndVerify_InvalidNonce(t *testing.T) {
	issuerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(holderPrivateKey.PublicKey.Y.Bytes()),
	}

	testClaim := "test_claim"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(issuerPrivateKey, "key-1")

	client := New()
	sdJWT, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer, vctmRaw,
		[]byte(`{"test_claim": "value"}`),
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)
	require.NoError(t, err)

	kbJWT, err := CreateKeyBindingJWT(sdJWT, "nonce-1", "https://verifier.example.com", holderPrivateKey, "sha-256")
	require.NoError(t, err)

	combined := sdJWT + kbJWT

	result, err := client.ParseAndVerify(combined, &issuerPrivateKey.PublicKey, &VerificationOptions{
		ExpectedNonce:    "nonce-2",
		ExpectedAudience: "https://verifier.example.com",
	})
	if err == nil {
		t.Fatalf("Expected error for nonce mismatch, but got none. Result: %+v, KB Claims: %+v", result, result.KeyBindingClaims)
	}
	assert.Error(t, err)
	if result != nil {
		assert.False(t, result.Valid)
	}
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestParseDisclosure(t *testing.T) {
	client := New()
	hashMethod := sha256.New()

	// Create a valid disclosure
	disclosure := []any{"salt123", "claim_name", "claim_value"}
	disclosureJSON, err := json.Marshal(disclosure)
	require.NoError(t, err)

	disclosureStr := base64.RawURLEncoding.EncodeToString(disclosureJSON)

	// Parse it
	parsed, err := client.parseDisclosure(disclosureStr, hashMethod)
	require.NoError(t, err)
	assert.Equal(t, "salt123", parsed.Salt)
	assert.Equal(t, "claim_name", parsed.Claim)
	assert.Equal(t, "claim_value", parsed.Value)
	assert.NotEmpty(t, parsed.Hash)
}

func TestParseDisclosure_InvalidFormat(t *testing.T) {
	client := New()
	hashMethod := sha256.New()

	tests := []struct {
		name        string
		disclosure  []any
		expectError string
	}{
		{
			name:        "Too few elements",
			disclosure:  []any{"salt", "claim"},
			expectError: "expected 3 elements",
		},
		{
			name:        "Too many elements",
			disclosure:  []any{"salt", "claim", "value", "extra"},
			expectError: "expected 3 elements",
		},
		{
			name:        "Invalid salt type",
			disclosure:  []any{123, "claim", "value"},
			expectError: "salt must be string",
		},
		{
			name:        "Invalid claim type",
			disclosure:  []any{"salt", 456, "value"},
			expectError: "claim name must be string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disclosureJSON, err := json.Marshal(tt.disclosure)
			require.NoError(t, err)

			disclosureStr := base64.RawURLEncoding.EncodeToString(disclosureJSON)

			_, err = client.parseDisclosure(disclosureStr, hashMethod)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestValidateSDJWTVCStructure(t *testing.T) {
	client := New()

	tests := []struct {
		name        string
		header      map[string]any
		claims      map[string]any
		opts        *VerificationOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid dc+sd-jwt",
			header: map[string]any{
				"typ": "dc+sd-jwt",
				"alg": "ES256",
			},
			claims: map[string]any{
				"vct": "TestCredential",
				"iss": "https://issuer.example.com",
				"exp": float64(time.Now().Add(24 * time.Hour).Unix()),
			},
			opts:        &VerificationOptions{ValidateTime: true, AllowedClockSkew: 5 * time.Minute},
			expectError: false,
		},
		{
			name: "Valid vc+sd-jwt (backward compatibility)",
			header: map[string]any{
				"typ": "vc+sd-jwt",
				"alg": "ES256",
			},
			claims: map[string]any{
				"vct": "TestCredential",
			},
			opts:        &VerificationOptions{ValidateTime: false},
			expectError: false,
		},
		{
			name: "Invalid typ header",
			header: map[string]any{
				"typ": "invalid",
				"alg": "ES256",
			},
			claims: map[string]any{
				"vct": "TestCredential",
			},
			opts:        &VerificationOptions{ValidateTime: false},
			expectError: true,
			errorMsg:    "invalid typ header",
		},
		{
			name: "Missing vct claim",
			header: map[string]any{
				"typ": "dc+sd-jwt",
				"alg": "ES256",
			},
			claims: map[string]any{
				"iss": "https://issuer.example.com",
			},
			opts:        &VerificationOptions{ValidateTime: false},
			expectError: true,
			errorMsg:    "missing required claim: vct",
		},
		{
			name: "Expired credential",
			header: map[string]any{
				"typ": "dc+sd-jwt",
				"alg": "ES256",
			},
			claims: map[string]any{
				"vct": "TestCredential",
				"exp": float64(time.Now().Add(-24 * time.Hour).Unix()),
			},
			opts:        &VerificationOptions{ValidateTime: true, AllowedClockSkew: 5 * time.Minute},
			expectError: true,
			errorMsg:    "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateSDJWTVCStructure(tt.header, tt.claims, tt.opts)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReconstructClaims(t *testing.T) {
	client := New()

	claims := map[string]any{
		"vct":     "TestCredential",
		"iss":     "https://issuer.example.com",
		"_sd":     []any{"hash1", "hash2"},
		"_sd_alg": "sha-256",
	}

	disclosures := []Disclosure{
		{Claim: "name", Value: "John Doe"},
		{Claim: "age", Value: float64(30)},
	}

	err := client.reconstructClaims(claims, disclosures)
	require.NoError(t, err)

	// Disclosed claims should be added
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, float64(30), claims["age"])

	// _sd and _sd_alg should be removed
	assert.NotContains(t, claims, "_sd")
	assert.NotContains(t, claims, "_sd_alg")
}

func TestJWKToPublicKey_ECDSA(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create JWK map
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
	}

	// Convert to public key
	pubKey, err := jwkToPublicKey(jwkMap)
	require.NoError(t, err)

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, privateKey.PublicKey.X, ecdsaPubKey.X)
	assert.Equal(t, privateKey.PublicKey.Y, ecdsaPubKey.Y)
}

func TestJWKToPublicKey_InvalidFormat(t *testing.T) {
	tests := []struct {
		name        string
		jwkMap      map[string]any
		expectError string
	}{
		{
			name: "Missing x coordinate",
			jwkMap: map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"y":   "test",
			},
			expectError: "missing x or y coordinate",
		},
		{
			name: "Missing y coordinate",
			jwkMap: map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   "test",
			},
			expectError: "missing x or y coordinate",
		},
		{
			name: "Unsupported key type",
			jwkMap: map[string]any{
				"kty": "OKP",
			},
			expectError: "unsupported key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jwkToPublicKey(tt.jwkMap)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}
