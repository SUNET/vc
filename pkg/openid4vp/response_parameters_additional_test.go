package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseParameters_Validate(t *testing.T) {
	tests := []struct {
		name        string
		response    *ResponseParameters
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid response with SD-JWT VP token",
			response: &ResponseParameters{
				VPToken: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiZGMrc2Qtand0In0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjdCI6IlRlc3RDcmVkZW50aWFsIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.signature",
				State:   "test-state",
			},
			expectError: false,
		},
		{
			name: "missing vp_token",
			response: &ResponseParameters{
				State: "test-state",
			},
			expectError: true,
			errorMsg:    "vp_token is required",
		},
		{
			name: "invalid vp_token format",
			response: &ResponseParameters{
				VPToken: "invalid-token",
				State:   "test-state",
			},
			expectError: true,
			errorMsg:    "invalid vp_token format",
		},
		{
			name: "empty response",
			response: &ResponseParameters{
				VPToken: "",
			},
			expectError: true,
			errorMsg:    "vp_token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestResponseParameters_ToJSON(t *testing.T) {
	tests := []struct {
		name     string
		response *ResponseParameters
	}{
		{
			name: "full response",
			response: &ResponseParameters{
				VPToken: "token123",
				Code:    "code456",
				ISS:     "https://issuer.example.com",
				State:   "state789",
				IDToken: "idtoken123",
				PresentationSubmission: &PresentationSubmission{
					ID:           "sub1",
					DefinitionID: "def1",
				},
			},
		},
		{
			name: "minimal response",
			response: &ResponseParameters{
				VPToken: "token",
				State:   "state",
			},
		},
		{
			name:     "empty response",
			response: &ResponseParameters{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.response.ToJSON()
			require.NoError(t, err)
			assert.NotNil(t, data)

			// Verify it's valid JSON
			var decoded map[string]any
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
		})
	}
}

func TestResponseParametersFromJSON(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectError bool
		validate    func(t *testing.T, rp *ResponseParameters)
	}{
		{
			name: "full response",
			jsonData: `{
				"vp_token": "token123",
				"code": "code456",
				"iss": "https://issuer.example.com",
				"state": "state789",
				"id_token": "idtoken123"
			}`,
			expectError: false,
			validate: func(t *testing.T, rp *ResponseParameters) {
				assert.Equal(t, "token123", rp.VPToken)
				assert.Equal(t, "code456", rp.Code)
				assert.Equal(t, "https://issuer.example.com", rp.ISS)
				assert.Equal(t, "state789", rp.State)
				assert.Equal(t, "idtoken123", rp.IDToken)
			},
		},
		{
			name: "with presentation_submission",
			jsonData: `{
				"vp_token": "token",
				"state": "state",
				"presentation_submission": {
					"id": "sub1",
					"definition_id": "def1",
					"descriptor_map": []
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, rp *ResponseParameters) {
				assert.NotNil(t, rp.PresentationSubmission)
				assert.Equal(t, "sub1", rp.PresentationSubmission.ID)
				assert.Equal(t, "def1", rp.PresentationSubmission.DefinitionID)
			},
		},
		{
			name:        "invalid JSON",
			jsonData:    `{invalid json`,
			expectError: true,
		},
		{
			name:        "empty JSON object",
			jsonData:    `{}`,
			expectError: false,
			validate: func(t *testing.T, rp *ResponseParameters) {
				assert.Empty(t, rp.VPToken)
				assert.Empty(t, rp.State)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResponseParametersFromJSON([]byte(tt.jsonData))

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

func TestResponseParameters_RoundTrip(t *testing.T) {
	original := &ResponseParameters{
		VPToken: "token123",
		Code:    "code456",
		ISS:     "https://issuer.example.com",
		State:   "state789",
		IDToken: "idtoken123",
		PresentationSubmission: &PresentationSubmission{
			ID:           "sub1",
			DefinitionID: "def1",
		},
	}

	// Convert to JSON
	data, err := original.ToJSON()
	require.NoError(t, err)

	// Convert back to struct
	decoded, err := ResponseParametersFromJSON(data)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.VPToken, decoded.VPToken)
	assert.Equal(t, original.Code, decoded.Code)
	assert.Equal(t, original.ISS, decoded.ISS)
	assert.Equal(t, original.State, decoded.State)
	assert.Equal(t, original.IDToken, decoded.IDToken)
	assert.NotNil(t, decoded.PresentationSubmission)
	assert.Equal(t, original.PresentationSubmission.ID, decoded.PresentationSubmission.ID)
	assert.Equal(t, original.PresentationSubmission.DefinitionID, decoded.PresentationSubmission.DefinitionID)
}

func TestVPResponse(t *testing.T) {
	t.Run("create and marshal", func(t *testing.T) {
		vpResp := VPResponse{
			VPToken: map[string]string{
				"credential_1": "token1",
				"credential_2": "token2",
			},
			State: "test-state",
		}

		data, err := json.Marshal(vpResp)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		var decoded VPResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, vpResp.State, decoded.State)
		assert.Equal(t, len(vpResp.VPToken), len(decoded.VPToken))
		assert.Equal(t, vpResp.VPToken["credential_1"], decoded.VPToken["credential_1"])
	})
}
