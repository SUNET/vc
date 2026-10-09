package helpers

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Validation has to descend into each configured static client.
//
// OIDCOP.StaticClients carried no `dive`, so the constraints on
// StaticOIDCClient were never evaluated for a YAML client: a static client
// could name a grant type the OP does not implement, or omit a required
// redirect_uri, and still pass startup validation (SUNET/vc#756).
func TestStaticClientsAreValidatedIndividually(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	valid := model.StaticOIDCClient{
		ClientID:                "ok",
		ClientSecret:            "secret",
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
	}

	require.NoError(t, validate.Struct(opWith(valid)), "a well-formed static client must pass")

	for name, broken := range map[string]func(c *model.StaticOIDCClient){
		"a grant type the OP does not implement": func(c *model.StaticOIDCClient) {
			c.GrantTypes = []string{"refresh_token"}
		},
		"an unsupported token endpoint auth method": func(c *model.StaticOIDCClient) {
			c.TokenEndpointAuthMethod = "private_key_jwt"
		},
		"no redirect_uris": func(c *model.StaticOIDCClient) {
			c.RedirectURIs = nil
		},
		"an unsupported response type": func(c *model.StaticOIDCClient) {
			c.ResponseTypes = []string{"token"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := valid
			broken(&client)

			assert.Error(t, validate.Struct(opWith(client)),
				"validation did not descend into the static client")
		})
	}
}

// opWith is an otherwise-valid OIDCOP carrying one static client, so a
// failure can only come from that client.
func opWith(client model.StaticOIDCClient) *model.OIDCOP {
	return &model.OIDCOP{
		Issuer:              "https://verifier.example.com",
		SubjectType:         "public",
		SubjectSalt:         "salt",
		SessionDuration:     3600,
		CodeDuration:        300,
		AccessTokenDuration: 3600,
		IDTokenDuration:     3600,
		StaticClients:       []model.StaticOIDCClient{client},
	}
}

// A negative duration must be refused, not silently treated as unset.
//
// defaulting only fills a ZERO value, and `required` only rejects zero, so
// a negative survived both - and userSessionMaxAge, which guards with
// `> 0`, then mapped it to the old hardcoded 900 rather than the documented
// 3600. Now that this setting controls how long a session cookie stays
// decodable, silently inventing a value for it is the wrong answer
// (SUNET/vc#756).
func TestNegativeVerifierDurationsAreRefused(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	require.NoError(t, validate.Struct(opWith(model.StaticOIDCClient{
		ClientID: "ok", ClientSecret: "s",
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
	})), "the baseline must pass, or this test proves nothing")

	for name, break_ := range map[string]func(*model.OIDCOP){
		"session_duration":      func(op *model.OIDCOP) { op.SessionDuration = -1 },
		"code_duration":         func(op *model.OIDCOP) { op.CodeDuration = -1 },
		"access_token_duration": func(op *model.OIDCOP) { op.AccessTokenDuration = -1 },
		"id_token_duration":     func(op *model.OIDCOP) { op.IDTokenDuration = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			op := opWith(model.StaticOIDCClient{
				ClientID: "ok", ClientSecret: "s",
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			})
			break_(op)
			assert.Error(t, validate.Struct(op))
		})
	}

	// ... and the presentation window, on the inbound side.
	assert.Error(t, validate.Struct(&model.OpenID4VPConfig{
		PresentationTimeout:  -1,
		SupportedCredentials: []model.SupportedCredentialConfig{{}},
	}))
}
