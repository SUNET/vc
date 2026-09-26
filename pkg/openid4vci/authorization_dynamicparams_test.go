package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPARRequestDynamicParams_RejectsMongoUnsafeKeys guards against
// DynamicParams keys that MongoDB forbids in field names (a leading "$",
// interpreted as an operator, or any "." which MongoDB treats as a nested
// field-path separator) reaching AuthorizationContext.Save, where they would
// cause a persistence failure for the whole request.
//
// Validated through this package's own NewValidator, which is what the
// request is validated by in production. It used to build a bare validator
// and re-register safe_key from a copied pattern, explaining in a comment
// that pkg/helpers could not be imported here - true, and the reason
// RegisterSafeKey now lives in this package instead. Sharing the guard was
// the point; using the real constructor also means this test would have
// caught the panic that the missing registration caused.
func TestPARRequestDynamicParams_RejectsMongoUnsafeKeys(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"plain alphanumeric key", "acr_values", false},
		{"key with underscore", "authentic_source", false},
		{"key containing dot", "authentic.source", true},
		{"key starting with dollar", "$where", true},
		{"key with dollar in middle", "auth$source", true},
		{"key starting with digit", "1acr", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &PARRequest{
				ResponseType:        "code",
				ClientID:            "client",
				RedirectURI:         "https://example.com/cb",
				CodeChallenge:       "challenge",
				CodeChallengeMethod: "S256",
				DynamicParams:       map[string]string{tt.key: "value"},
			}
			// NewValidator reports fields by their json name.
			err := validate.Struct(req)
			if tt.wantErr {
				require.Error(t, err, "expected key %q to be rejected", tt.key)
			} else {
				if err != nil {
					require.NotContains(t, err.Error(), "dynamic_params", "key %q should not fail DynamicParams validation", tt.key)
				}
			}
		})
	}
}
