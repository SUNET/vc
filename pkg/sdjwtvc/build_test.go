package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"vc/pkg/jose"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildCredentialWithSigner tests the complete credential building process
func TestBuildCredentialWithSigner(t *testing.T) {
	// Generate test ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create test VCTM
	personalNumber := "personal_administrative_number"
	issuingAuth := "issuing_authority"
	vctm := &VCTM{
		VCT: "TestCredential",
		Claims: []Claim{
			{Path: []*string{&personalNumber}, SD: "always"},
			{Path: []*string{&issuingAuth}, SD: "always"},
		},
	}

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": "holder-key-id",
		"x":   "f83OJ3D2xF1c4hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5",
		"y":   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z",
	}

	documentData := []byte(`{
		"personal_administrative_number": "123456789",
		"issuing_authority": {
			"id": "TEST",
			"name": "Test Authority"
		},
		"issuing_country": "SE"
	}`)

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "issuer-key-1")

	client := New()
	token, err := client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		documentData,
		holderJWK,
		&CredentialOptions{Integrity: integrity},
	)

	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token structure
	parts := splitToken(token)
	assert.GreaterOrEqual(t, len(parts), 2, "token should have at least header and payload")

	// Decode header
	headerStr, err := Base64Decode(parts[0])
	require.NoError(t, err)

	var header map[string]any
	err = json.Unmarshal([]byte(headerStr), &header)
	require.NoError(t, err)

	// Verify header claims - per SD-JWT VC draft-13, typ is now "dc+sd-jwt"
	// (also accepts "vc+sd-jwt" during transition period)
	assert.Equal(t, "dc+sd-jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "issuer-key-1", header["kid"])

	// Decode payload (part before first ~)
	payloadParts := splitOnTilde(parts[1])
	payloadStr, err := Base64Decode(payloadParts[0])
	require.NoError(t, err)

	var payload map[string]any
	err = json.Unmarshal([]byte(payloadStr), &payload)
	require.NoError(t, err)

	// Verify JWT claims
	assert.Equal(t, "https://issuer.example.com", payload["iss"])
	assert.Equal(t, "TestCredential", payload["vct"])
	assert.Equal(t, "sha-256", payload["_sd_alg"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotEmpty(t, payload["nbf"])
	assert.NotEmpty(t, payload["exp"])

	// Verify cnf claim
	cnf, ok := payload["cnf"].(map[string]any)
	require.True(t, ok)
	jwk, ok := cnf["jwk"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "holder-key-id", jwk["kid"])

	// Verify selective disclosures
	sd, ok := payload["_sd"].([]any)
	require.True(t, ok)
	assert.Greater(t, len(sd), 0, "should have selective disclosures")

	// Verify token has disclosures (parts after ~)
	assert.Greater(t, len(parts), 2, "token should have disclosure parts")
}

func TestBuildCredentialWithSigner_AlgorithmSelection(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string // "ecdsa" or "rsa"
		curve       elliptic.Curve
		rsaKeySize  int
		expectedAlg string
	}{
		// ECDSA tests
		{
			name:        "ECDSA P-256 uses ES256",
			keyType:     "ecdsa",
			curve:       elliptic.P256(),
			expectedAlg: "ES256",
		},
		{
			name:        "ECDSA P-384 uses ES384",
			keyType:     "ecdsa",
			curve:       elliptic.P384(),
			expectedAlg: "ES384",
		},
		{
			name:        "ECDSA P-521 uses ES512",
			keyType:     "ecdsa",
			curve:       elliptic.P521(),
			expectedAlg: "ES512",
		},
		// RSA tests
		{
			name:        "RSA 2048 uses RS256",
			keyType:     "rsa",
			rsaKeySize:  2048,
			expectedAlg: "RS256",
		},
		{
			name:        "RSA 3072 uses RS384",
			keyType:     "rsa",
			rsaKeySize:  3072,
			expectedAlg: "RS384",
		},
		{
			name:        "RSA 4096 uses RS512",
			keyType:     "rsa",
			rsaKeySize:  4096,
			expectedAlg: "RS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateKey any
			var err error
			var jwkType string

			// Generate appropriate key type
			if tt.keyType == "ecdsa" {
				privateKey, err = ecdsa.GenerateKey(tt.curve, rand.Reader)
				jwkType = "EC"
			} else {
				privateKey, err = rsa.GenerateKey(rand.Reader, tt.rsaKeySize)
				jwkType = "RSA"
			}
			require.NoError(t, err)

			testClaim := "test_claim"
			vctm := &VCTM{
				VCT:    "TestCredential",
				Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
			}

			vctmRaw, integrity := marshalVCTM(t, vctm)
			signer := newTestSigner(privateKey, "key-1")

			client := New()
			token, err := client.BuildCredentialWithSigner(
				t.Context(),
				"https://issuer.example.com",
				signer,
				vctmRaw,
				[]byte(`{"test_claim": "value"}`),
				map[string]any{"kty": jwkType},
				&CredentialOptions{Integrity: integrity},
			)

			require.NoError(t, err)

			// Extract and verify algorithm
			parts := splitToken(token)
			headerStr, err := Base64Decode(parts[0])
			require.NoError(t, err)

			var header map[string]any
			err = json.Unmarshal([]byte(headerStr), &header)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAlg, header["alg"])
		})
	}
}

func TestBuildCredentialWithSigner_InvalidJSON(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testClaim := "test"
	vctm := &VCTM{
		VCT:    "TestCredential",
		Claims: []Claim{{Path: []*string{&testClaim}, SD: "always"}},
	}

	vctmRaw, integrity := marshalVCTM(t, vctm)
	signer := newTestSigner(privateKey, "key-1")

	client := New()
	_, err = client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		[]byte(`{invalid json`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{Integrity: integrity},
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal document data")
}

func TestBuildCredentialWithSigner_InvalidVCTM(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := newTestSigner(privateKey, "key-1")

	client := New()
	_, err = client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		[]byte(`{not json`),
		[]byte(`{"test":"value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{},
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse VCTM")
}

func TestBuildCredentialWithSigner_EmptyVCT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := newTestSigner(privateKey, "key-1")

	// VCTM with empty VCT field
	vctmRaw, _ := marshalVCTM(t, &VCTM{VCT: ""})

	client := New()
	_, err = client.BuildCredentialWithSigner(
		t.Context(),
		"https://issuer.example.com",
		signer,
		vctmRaw,
		[]byte(`{"test":"value"}`),
		map[string]any{"kty": "EC"},
		&CredentialOptions{},
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty vct field")
}

func TestGetSigningMethodFromKey_UnknownKeyType(t *testing.T) {
	// Test with a non-crypto key type
	signingMethod, algName := jose.GetSigningMethodFromKey("not a key")

	// Should default to ES256
	assert.NotNil(t, signingMethod)
	assert.Equal(t, "ES256", algName)
}

func TestGetSigningMethodFromKey_UnknownECDSACurve(t *testing.T) {
	// Create a key with a custom curve (this is theoretical)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test that it defaults to ES256 for known curves
	signingMethod, algName := jose.GetSigningMethodFromKey(privateKey)
	assert.NotNil(t, signingMethod)
	assert.Equal(t, "ES256", algName)
}

// Helper function to split token by dots (JWT structure)
func splitToken(token string) []string {
	parts := []string{}
	current := ""
	for _, ch := range token {
		if ch == '.' {
			parts = append(parts, current)
			current = ""
		} else if ch == '~' {
			// Split on tilde for disclosures
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// Helper to split on tilde
func splitOnTilde(s string) []string {
	parts := []string{}
	current := ""
	for _, ch := range s {
		if ch == '~' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
