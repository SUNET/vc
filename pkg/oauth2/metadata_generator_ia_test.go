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
	base := &MetadataConfig{IssuerURL: "https://issuer.example.com", TokenEndpoint: "https://issuer.example.com/token"}

	t.Run("absent unless configured", func(t *testing.T) {
		got := metadataJSON(t, base)
		assert.NotContains(t, got, "authorization_challenge_endpoint")
		assert.NotContains(t, got, "require_interactive_authorization")
	})

	t.Run("the endpoint is advertised when set", func(t *testing.T) {
		cfg := *base
		cfg.AuthorizationChallengeEndpoint = "https://issuer.example.com/op/authorize-challenge"
		got := metadataJSON(t, &cfg)

		assert.Equal(t, "https://issuer.example.com/op/authorize-challenge", got["authorization_challenge_endpoint"])
		assert.NotContains(t, got, "require_interactive_authorization",
			"false is the default and omitempty keeps it off the wire")
	})

	t.Run("required is advertised alongside the endpoint", func(t *testing.T) {
		cfg := *base
		cfg.AuthorizationChallengeEndpoint = "https://issuer.example.com/op/authorize-challenge"
		cfg.RequireInteractiveAuthorization = true
		got := metadataJSON(t, &cfg)

		assert.Equal(t, true, got["require_interactive_authorization"])
	})

	t.Run("required without the endpoint is dropped, not emitted", func(t *testing.T) {
		// The specification forbids the pair, and the document would be
		// unusable: a wallet is told the only accepted path to issuance is
		// a mechanism this server does not expose. GenerateMetadata cannot
		// report an error, so it refuses to emit it; the struct's own
		// excluded_without rule refuses the same combination wherever the
		// metadata is validated, including before it is signed.
		cfg := *base
		cfg.RequireInteractiveAuthorization = true
		got := metadataJSON(t, &cfg)

		assert.NotContains(t, got, "require_interactive_authorization")
		assert.NotContains(t, got, "authorization_challenge_endpoint")
	})
}

// The signing path never goes through GenerateMetadata: SignMetadata
// unmarshals a configured document straight into this struct. A guard that
// lives only in the generator therefore does nothing for it, and a SIGNED
// document advertising a requirement for an endpoint it does not publish
// is worse than an unsigned one - a wallet has every reason to trust it.
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
