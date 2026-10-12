package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/go-playground/validator/v10"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func metadataJSON(t *testing.T, cfg *MetadataConfig) map[string]any {
	t.Helper()
	body, err := json.Marshal(GenerateMetadata(cfg))
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	return got
}

// The presence of authorization_challenge_endpoint is the entire signal
// that Interactive Authorization is available, so a deployment that has
// not enabled it must emit neither parameter.
func TestGenerateMetadata_InteractiveAuthorization(t *testing.T) {
	const endpoint = "https://issuer.example.com/op/authorize-challenge"

	for _, tt := range []struct {
		name         string
		endpoint     string
		require      bool
		wantEndpoint any // nil = the member must be absent
		wantRequire  any // nil = the member must be absent
	}{
		// The presence of authorization_challenge_endpoint is the entire
		// signal that Interactive Authorization is available, so a
		// deployment that has not enabled it emits neither parameter.
		{name: "absent unless configured"},
		{name: "the endpoint is advertised when set", endpoint: endpoint, wantEndpoint: endpoint},
		{name: "required is advertised alongside the endpoint", endpoint: endpoint, require: true, wantEndpoint: endpoint, wantRequire: true},
		// The specification forbids the pair, and the document would be
		// unusable: a wallet is told the only accepted path to issuance is
		// a mechanism this server does not expose. GenerateMetadata cannot
		// report an error, so it refuses to emit it; the struct's own
		// excluded_without rule refuses the same combination wherever the
		// metadata is validated, including before it is signed.
		{name: "required without the endpoint is dropped, not emitted", require: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := metadataJSON(t, &MetadataConfig{
				IssuerURL:                       "https://issuer.example.com",
				TokenEndpoint:                   "https://issuer.example.com/token",
				AuthorizationChallengeEndpoint:  tt.endpoint,
				RequireInteractiveAuthorization: tt.require,
			})

			for key, want := range map[string]any{
				"authorization_challenge_endpoint":  tt.wantEndpoint,
				"require_interactive_authorization": tt.wantRequire,
			} {
				if want == nil {
					assert.NotContains(t, got, key)
					continue
				}
				assert.Equal(t, want, got[key])
			}
		})
	}
}

// validMetadata is the smallest document that satisfies every other
// required field, so these subtests vary only the two Interactive
// Authorization members.
func validMetadata() *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		Issuer:                 "https://issuer.example.com",
		AuthorizationEndpoint:  "https://issuer.example.com/authorize",
		TokenEndpoint:          "https://issuer.example.com/token",
		ResponseTypesSupported: []string{"code"},
	}
}

func TestRequireInteractiveAuthorizationIsRefusedByValidation(t *testing.T) {
	validate := validator.New()

	t.Run("required without the endpoint does not validate", func(t *testing.T) {
		m := validMetadata()
		m.RequireInteractiveAuthorization = true

		err := validate.Struct(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RequireInteractiveAuthorization")
	})

	t.Run("required with the endpoint validates", func(t *testing.T) {
		m := validMetadata()
		m.AuthorizationChallengeEndpoint = "https://issuer.example.com/op/authorize-challenge"
		m.RequireInteractiveAuthorization = true

		assert.NoError(t, validate.Struct(m))
	})

	t.Run("the endpoint alone validates", func(t *testing.T) {
		m := validMetadata()
		m.AuthorizationChallengeEndpoint = "https://issuer.example.com/op/authorize-challenge"

		assert.NoError(t, validate.Struct(m))
	})

	t.Run("neither is fine", func(t *testing.T) {
		assert.NoError(t, validate.Struct(validMetadata()))
	})
}
