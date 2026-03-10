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

func TestVerifyZKP(t *testing.T) {
	ctx := t.Context()

	// The raw data you provided
	transcript := "g/b2gnZPcGVuSUQ0VlBEQ0FQSUhhbmRvdmVyWCC+g0qI5l1IQfgYZpodKs/I+r9axTucmuRDCE4W/HiSvQ=="
	deviceCBOR := "o2ZzdGF0dXMAZ3ZlcnNpb25jMS4wa3prRG9jdW1lbnRzgVoABPMtpmVwcm9vZloABO8cBl/zQjOdsnMZHd94B/7F/o+tQ88yhbGms3Nwlbf1F82o+mxjNyGarvvs0ezHRREhEMDiFGRSkFIvXjEe59XWKYX3+Wefy/eguO6DVHXUYUuLxrD4Dw2USgiXJYx4cT5h6V1nNqsgfi+G4LdckWZaCcW26AqGokuZgiFj2tabcYFuJ47Leo7OgAyL69SBwWq+9xfQg62Igo6jNy3j8Du/vZ7BiyGyjESyn2gai5MBTJVH1xtbTL2KHSkQr16q1jjTzrruKLyks2gLD0nvusOtrO0woZGax/vmnu3G8dnBrzpsxfQ2FnKh8RrjwFN5dSRye3Fm9HRvgNiXIs80y4L/8mmjrjOm41NzOswqIHJle9XDs3zepQK80oZ2dTzB5D5fRTMrYVopZgFOmkvjy+VjcnHgYZGDjFJ46JVAcQU3pEg2In1olxPPPcJdco3USV5ypiLL4lScC0qW6fPl7UvYwfdz8HLbrKN0J2uX+JaOxn53nMlXljBrIndYtHGbqPUWZU/qKHlq0x0bqRzq1uHST2FaAI4KWk44Uf0nDXsekGc+XJzXRdjtEdmn8MYsff4okD4swF8iZN8HQulQQT6x4XtPEqV15ms4VdHQa2IhhG9y0JJ/9Mo4l/qKEc0Ss6S4d4LniYO1/4CU5ob1PaknzbcnZzyMwKhRA7jLdV4zPFvXs5XasJ13HkofZ0iY9YKiR1qNmq3i5DALsOoitN9sAUD1M3gVhYMmKJDsUrrllvCoYDyap1aoSSk7N0pxtv/NIwtgES42rxejQpu0q9PeJQESuI3hzqytkhkYVUd0E+N3F7HGDjeATC82TH0wmZBvU4o1z24gipwashce7I5utNKcwDfDEKVzHe/vLkM1Vr7/aonIBMH93uoXF6bnQbfRWjIMUFwjuc/ppSCeoZqZ8qBD6GJJ59AzeeTk0LRTs5YOTeLg/yFnqCpgaFVOSc5eWOLtuZlUkk3PfG7fDAGPmagU6Q2xhUXyHe80hFOUCrY4K9Gc56RHYDdgNnUyLpkub5bn0MGq0uQSLxNjFHf6X3KDOtFrApUIsLdEWpYxBWTDebIrc+7fsMqtWer+6f0zZ8Aud2YtbL0pe_REDACTED_FOR_BREVITY_vmuRuX..."

	tests := []struct {
		name        string
		req         *VerifyZKPRequest
		expectError bool
	}{
		{
			name: "process valid base64 payload",
			req: &VerifyZKPRequest{
				Transcript:           transcript,
				ZKDeviceResponseCBOR: deviceCBOR,
			},
			expectError: false,
		},
		{
			name: "fail on malformed base64 transcript",
			req: &VerifyZKPRequest{
				Transcript:           "invalid-base64-!@#",
				ZKDeviceResponseCBOR: deviceCBOR,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup client with necessary mocks/loggers
			client, _ := CreateTestClientWithMock(nil)

			resp, err := client.VerifyZKP(ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				_, ok := resp.Claims["org.iso.18013.5.1"]
				assert.True(t, ok, "Should contain the ISO namespace key")
			}
		})
	}
}
