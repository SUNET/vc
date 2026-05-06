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

	verifier := trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trust.NewAllowAllEvaluator(),
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            logger.NewSimple("test"),
	})

	ctx := context.Background()
	err = verifier.EvaluateIssuerTrust(ctx, signedJWT+"~", testScope)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT signature verification failed")
}
