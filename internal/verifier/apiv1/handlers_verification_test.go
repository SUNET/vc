package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testScope = "test-scope"

// TestGetKID tests the GetKID method on VerificationDirectPostRequest
func TestGetKID(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		expectedKID string
		expectError bool
	}{
		{
			name:        "valid JWT with KID",
			response:    createTestJWEWithKID("test-kid-123"),
			expectedKID: "test-kid-123",
			expectError: false,
		},
		{
			name:        "JWT with different KID",
			response:    createTestJWEWithKID("another-kid-456"),
			expectedKID: "another-kid-456",
			expectError: false,
		},
		{
			name:        "JWT without KID",
			response:    createTestJWEWithoutKID(),
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "malformed base64 header",
			response:    "!!!invalid-base64!!!.payload.signature",
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "malformed JSON header",
			response:    base64.RawStdEncoding.EncodeToString([]byte("not-json")) + ".payload.signature",
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "KID is not a string",
			response:    createTestJWEWithNonStringKID(),
			expectedKID: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &VerificationDirectPostRequest{
				Response: tt.response,
			}

			kid, err := req.GetKID()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedKID, kid)
			}
		})
	}
}

// Helper functions for GetKID tests

func createTestJWEWithKID(kid string) string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": kid,
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

func createTestJWEWithoutKID() string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

func createTestJWEWithNonStringKID() string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": 12345, // Integer instead of string
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

// TestVerificationCallback tests the VerificationCallback handler
func TestVerificationCallback(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		responseCode      string
		setupCache        bool
		expectedCredCount int
		expectError       bool
	}{
		{
			name:              "successful callback with cached credential",
			responseCode:      "valid-response-code",
			setupCache:        true,
			expectedCredCount: 1,
			expectError:       false,
		},
		{
			name:         "response code not found in cache",
			responseCode: "non-existent-code",
			setupCache:   false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup credential cache if needed
			if tt.setupCache {
				credentials := []sdjwtvc.CredentialCache{
					{
						Credential: map[string]any{
							"vct": "urn:credential:diploma",
						},
						Claims: []sdjwtvc.Discloser{
							{ClaimName: "given_name", Value: "John"},
							{ClaimName: "family_name", Value: "Doe"},
						},
					},
				}
				client.cacheService.Credential.Set(ctx, tt.responseCode, credentials)
			}

			req := &VerificationCallbackRequest{
				ResponseCode: tt.responseCode,
			}

			resp, err := client.VerificationCallback(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.Len(t, resp.CredentialData, tt.expectedCredCount)
			}
		})
	}
}

// TestBuildAllowedAlgorithmSet tests algorithm allowlist construction
func TestBuildAllowedAlgorithmSet(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		expectAlg   string
		expectAllow bool
	}{
		{
			name:        "ES256 allowed by default",
			input:       nil,
			expectAlg:   "ES256",
			expectAllow: true,
		},
		{
			name:        "ES256 explicitly allowed",
			input:       []string{"ES256", "ES384"},
			expectAlg:   "ES256",
			expectAllow: true,
		},
		{
			name:        "RS256 not in custom list",
			input:       []string{"ES256"},
			expectAlg:   "RS256",
			expectAllow: false,
		},
		{
			name:        "none algorithm stripped even if in list",
			input:       []string{"none", "ES256"},
			expectAlg:   "none",
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := trust.BuildAllowedAlgorithmSet(tt.input)
			assert.Equal(t, tt.expectAllow, allowed[tt.expectAlg])
		})
	}
}

// TestValidateSigningMethodForKey tests signing method / key type compatibility
func TestValidateSigningMethodForKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// ECDSA key with ECDSA method - should pass
	ecToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{})
	err = trust.ValidateSigningMethodForKey(ecToken, &ecKey.PublicKey)
	assert.NoError(t, err)

	// ECDSA key with RSA method - should fail
	rsaToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{})
	err = trust.ValidateSigningMethodForKey(rsaToken, &ecKey.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

// TestVerifyJWTSignatureInvalidSignature tests that invalid signatures are rejected via JWTTrustVerifier
func TestVerifyJWTSignatureInvalidSignature(t *testing.T) {
	// Generate two different keys
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Sign with key1, embed key2 in jwk header (mismatch)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "test-issuer",
	})
	// Embed key2's public key as jwk so extractJWTKeyMaterial uses key2
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key2.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key2.PublicKey.Y.Bytes()),
	}
	signedJWT, err := token.SignedString(key1)
	require.NoError(t, err)

	verifier := newTestJWTTrustVerifier(&mockTrustEvaluator{trustDecision: true})

	ctx := context.Background()
	err = verifier.EvaluateIssuerTrust(ctx, signedJWT+"~", testScope)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT signature verification failed")
}

// newTestJWTTrustVerifier creates a JWTTrustVerifier for testing.
func newTestJWTTrustVerifier(evaluator trust.TrustEvaluator) *trust.JWTTrustVerifier {
	return trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: evaluator,
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            logger.NewSimple("test"),
	})
}

// mockTrustEvaluator is a mock implementation for testing
type mockTrustEvaluator struct {
	trustDecision bool
	trustReason   string
	shouldError   bool
}

func (m *mockTrustEvaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return &trustapi.TrustDecision{
		Trusted:        m.trustDecision,
		Reason:         m.trustReason,
		TrustFramework: "test-framework",
	}, nil
}

func (m *mockTrustEvaluator) SupportsKeyType(kt trust.KeyType) bool {
	return true
}

// TestEvaluateIssuerTrust_NilEvaluator tests that nil trust evaluator returns error
func TestEvaluateIssuerTrustNilEvaluator(t *testing.T) {
	verifier := trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		Log: logger.NewSimple("test"),
	})

	ctx := context.Background()
	err := verifier.EvaluateIssuerTrust(ctx, "dummy.jwt.token", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust evaluator not initialized")
}

// TestEvaluateIssuerTrust_EmptyJWT tests that empty JWT returns error
func TestEvaluateIssuerTrustEmptyJWT(t *testing.T) {
	verifier := newTestJWTTrustVerifier(&mockTrustEvaluator{trustDecision: true})

	ctx := context.Background()
	err := verifier.EvaluateIssuerTrust(ctx, "", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty issuer JWT")
}

// TestEvaluateIssuerTrust_MissingKeyMaterial tests that missing key material returns error
func TestEvaluateIssuerTrustMissingKeyMaterial(t *testing.T) {
	verifier := newTestJWTTrustVerifier(&mockTrustEvaluator{trustDecision: true})

	// Create a JWT without x5c or jwk header and non-DID issuer
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com", // Not a DID
		"vct": "urn:credential:test",
	})
	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	err = verifier.EvaluateIssuerTrust(ctx, signedJWT+"~disclosure1~disclosure2~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing x5c, jwk, or kid header")
}
