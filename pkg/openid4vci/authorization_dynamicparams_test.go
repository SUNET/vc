package openid4vci

import (
	"regexp"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"
)

// TestPARRequestDynamicParams_RejectsMongoUnsafeKeys guards against
// DynamicParams keys that MongoDB forbids in field names (a leading "$",
// interpreted as an operator, or any "." which MongoDB treats as a nested
// field-path separator) reaching AuthorizationContext.Save, where they would
// cause a persistence failure for the whole request.
//
// This registers "safe_key" locally with the same pattern as
// pkg/helpers/validate.go's registration (which pkg/openid4vci cannot import
// here: pkg/helpers -> pkg/model -> pkg/openid4vci would be a cycle) purely
// to exercise the validate tag on PARRequest.DynamicParams in isolation.
func TestPARRequestDynamicParams_RejectsMongoUnsafeKeys(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	safeKeyRe := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
	require.NoError(t, validate.RegisterValidation("safe_key", func(fl validator.FieldLevel) bool {
		return safeKeyRe.MatchString(fl.Field().String())
	}))

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
			err := validate.Struct(req)
			if tt.wantErr {
				require.Error(t, err, "expected key %q to be rejected", tt.key)
			} else {
				if err != nil {
					require.NotContains(t, err.Error(), "DynamicParams", "key %q should not fail DynamicParams validation", tt.key)
				}
			}
		})
	}
}
