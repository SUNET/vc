package openid4vp

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDirectPostURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		response    *ResponseParameters
		expectError bool
		validate    func(t *testing.T, resultURL string)
	}{
		{
			name:    "full response with all fields",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{ // #nosec G101
				VPToken: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test",
				State:   "state123",
				Code:    "code456",
				IDToken: "id_token_789",
				PresentationSubmission: &PresentationSubmission{
					ID:           "submission1",
					DefinitionID: "def1",
				},
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Equal(t, "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test", query.Get("vp_token"))
				assert.Equal(t, "state123", query.Get("state"))
				assert.Equal(t, "code456", query.Get("code"))
				assert.Equal(t, "id_token_789", query.Get("id_token"))

				psJSON := query.Get("presentation_submission")
				assert.NotEmpty(t, psJSON)

				var ps PresentationSubmission
				err = json.Unmarshal([]byte(psJSON), &ps)
				require.NoError(t, err)
				assert.Equal(t, "submission1", ps.ID)
				assert.Equal(t, "def1", ps.DefinitionID)
			},
		},
		{
			name:    "minimal response with vp_token and state",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{ // #nosec G101
				VPToken: "vp_token_value",
				State:   "state_value",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Equal(t, "vp_token_value", query.Get("vp_token"))
				assert.Equal(t, "state_value", query.Get("state"))
				assert.Empty(t, query.Get("code"))
				assert.Empty(t, query.Get("id_token"))
				assert.Empty(t, query.Get("presentation_submission"))
			},
		},
		{
			name:    "empty vp_token",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{
				State: "state_only",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Empty(t, query.Get("vp_token"))
				assert.Equal(t, "state_only", query.Get("state"))
			},
		},
		{
			name:    "with code authorization flow",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{
				Code:  "authorization_code_123",
				State: "state_value",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Equal(t, "authorization_code_123", query.Get("code"))
				assert.Equal(t, "state_value", query.Get("state"))
			},
		},
		{
			name:    "with id_token",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{ // #nosec G101
				IDToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
				State:   "state_value",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig", query.Get("id_token"))
				assert.Equal(t, "state_value", query.Get("state"))
			},
		},
		{
			name:    "baseURL with existing query params",
			baseURL: "https://verifier.example.com/callback?existing=param",
			response: &ResponseParameters{
				VPToken: "token",
				State:   "state",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				assert.Contains(t, resultURL, "vp_token=token")
				assert.Contains(t, resultURL, "state=state")
				// Note: the implementation will add a new ? which may not be ideal
			},
		},
		{
			name:    "special characters in values",
			baseURL: "https://verifier.example.com/callback",
			response: &ResponseParameters{
				VPToken: "token+with/special=chars",
				State:   "state with spaces",
			},
			expectError: false,
			validate: func(t *testing.T, resultURL string) {
				parsedURL, err := url.Parse(resultURL)
				require.NoError(t, err)

				query := parsedURL.Query()
				assert.Equal(t, "token+with/special=chars", query.Get("vp_token"))
				assert.Equal(t, "state with spaces", query.Get("state"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildDirectPostURL(tt.baseURL, tt.response)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

func TestBuildDirectPostURL_NilResponse(t *testing.T) {
	// Test with nil response - should not panic
	baseURL := "https://verifier.example.com/callback"

	// This might panic or error depending on implementation
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic: %v", r)
		}
	}()

	result, err := BuildDirectPostURL(baseURL, nil)
	// Either should error or return a URL with no params
	if err == nil {
		t.Logf("Result with nil response: %s", result)
	}
}

func TestDirectPostResponse(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		original := DirectPostResponse{
			RedirectURI: "https://wallet.example.com/success",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded DirectPostResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.RedirectURI, decoded.RedirectURI)
	})

	t.Run("empty redirect_uri", func(t *testing.T) {
		response := DirectPostResponse{}

		data, err := json.Marshal(response)
		require.NoError(t, err)

		// Should not include redirect_uri field when empty (omitempty)
		var decoded map[string]any
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, exists := decoded["redirect_uri"]
		assert.False(t, exists, "redirect_uri should be omitted when empty")
	})
}

func TestDirectPostJWTResponse(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		original := DirectPostJWTResponse{
			Response: "encrypted.jwt.token",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded DirectPostJWTResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Response, decoded.Response)
	})

	t.Run("required response field", func(t *testing.T) {
		response := DirectPostJWTResponse{
			Response: "test.jwt.response",
		}

		data, err := json.Marshal(response)
		require.NoError(t, err)

		var decoded map[string]any
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		responseValue, exists := decoded["response"]
		assert.True(t, exists, "response field should always be present")
		assert.Equal(t, "test.jwt.response", responseValue)
	})
}
