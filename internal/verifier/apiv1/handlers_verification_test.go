package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				client.credentialCache.Set(tt.responseCode, credentials, 0)
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
