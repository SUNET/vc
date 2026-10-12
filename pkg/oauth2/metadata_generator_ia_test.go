package oauth2

import (
	"encoding/json"
	"testing"

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
		// report an error, so it refuses to emit it; the configuration
		// layer rejects the same combination with a message.
		cfg := *base
		cfg.RequireInteractiveAuthorization = true
		got := metadataJSON(t, &cfg)

		assert.NotContains(t, got, "require_interactive_authorization")
		assert.NotContains(t, got, "authorization_challenge_endpoint")
	})
}
