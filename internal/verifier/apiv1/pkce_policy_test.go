package apiv1

import (
	"testing"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
)

func ptr(b bool) *bool { return &b }

// A public client holds no secret, so PKCE is the only thing binding an
// authorization code to whoever asked for it (RFC 9700 2.1.1). No
// configuration may waive it, and neither may a stored flag that was never
// set - the check comes before the flag precisely so a db.Client built
// somewhere that forgets it cannot produce an unprotected public client.
func TestPKCEIsNeverWaivableForAPublicClient(t *testing.T) {
	for _, requirePKCE := range []bool{true, false} {
		client := &db.Client{
			ClientID:                "public",
			TokenEndpointAuthMethod: "none",
			RequirePKCE:             requirePKCE,
		}
		assert.True(t, pkceRequired(client),
			"a public client with RequirePKCE=%v was let through", requirePKCE)
	}
}

// A confidential client follows its resolved flag, so an operator can
// exempt one that cannot send a code_challenge yet.
func TestPKCEFollowsTheFlagForAConfidentialClient(t *testing.T) {
	assert.True(t, pkceRequired(&db.Client{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: true}))
	assert.False(t, pkceRequired(&db.Client{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: false}))
}

// Static clients had no PKCE at all and no way to ask for it: the db.Client
// built from YAML never set the flag (SUNET/vc#757).
func TestStaticClientPKCEPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		static model.StaticOIDCClient
		op     *model.OIDCOP
		want   bool
	}{
		{
			name:   "required by default",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     &model.OIDCOP{},
			want:   true,
		},
		{
			name:   "required when the policy says so",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     &model.OIDCOP{RequirePKCE: ptr(true)},
			want:   true,
		},
		{
			name:   "the policy can exempt a confidential client",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     &model.OIDCOP{RequirePKCE: ptr(false)},
			want:   false,
		},
		{
			name:   "one client can be exempted without relaxing the policy",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: ptr(false)},
			op:     &model.OIDCOP{RequirePKCE: ptr(true)},
			want:   false,
		},
		{
			name:   "one client can be held to it while the policy is relaxed",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: ptr(true)},
			op:     &model.OIDCOP{RequirePKCE: ptr(false)},
			want:   true,
		},
		{
			name:   "a public client is required even with the policy off",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "none"},
			op:     &model.OIDCOP{RequirePKCE: ptr(false)},
			want:   true,
		},
		{
			name:   "a public client is required even when exempted by name",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "none", RequirePKCE: ptr(false)},
			op:     &model.OIDCOP{RequirePKCE: ptr(false)},
			want:   true,
		},
		{
			name:   "no oidc_provider section is still required",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     nil,
			want:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, staticClientRequiresPKCE(tc.static, tc.op))
		})
	}
}

// authorizeNoPKCE runs /authorize for clientID with no code_challenge.
func authorizeNoPKCE(t *testing.T, client *Client, clientID string) error {
	t.Helper()

	_, err := client.Authorize(t.Context(), &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     clientID,
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid",
		State:        "state",
		Nonce:        "nonce",
	})
	return err
}

// A static client reaching /authorize without a code_challenge is refused.
//
// It was not: getClientByID built its db.Client without RequirePKCE, so the
// flag was false and the check at handler_oidc.go never fired - while
// discovery advertised code_challenge_methods_supported (SUNET/vc#757).
func TestAuthorizeRefusesAStaticClientWithoutPKCE(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.StaticClients = []model.StaticOIDCClient{{
		ClientID:                "static-client",
		ClientSecret:            "secret",
		RedirectURIs:            []string{"https://example.com/callback"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}}
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid"}))

	assert.ErrorIs(t, authorizeNoPKCE(t, client, "static-client"), ErrInvalidRequest)
}

// ... and an operator can still exempt one, which is what makes the test
// above a policy test rather than a constant.
func TestAuthorizeAllowsAnExemptedStaticClientWithoutPKCE(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.StaticClients = []model.StaticOIDCClient{{
		ClientID:                "legacy-client",
		ClientSecret:            "secret",
		RedirectURIs:            []string{"https://example.com/callback"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		RequirePKCE:             ptr(false),
	}}
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid"}))

	assert.NoError(t, authorizeNoPKCE(t, client, "legacy-client"))
}

// A public static client cannot be exempted, however the config is written.
func TestAuthorizeRefusesAPublicStaticClientEvenWhenExempted(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.RequirePKCE = ptr(false)
	client.cfg.Verifier.Outbound.OIDCProvider.StaticClients = []model.StaticOIDCClient{{
		ClientID:                "public-client",
		RedirectURIs:            []string{"https://example.com/callback"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: "none",
		RequirePKCE:             ptr(false),
	}}
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid"}))

	assert.ErrorIs(t, authorizeNoPKCE(t, client, "public-client"), ErrInvalidRequest)
}

// A dynamically registered client cannot register itself out of PKCE.
//
// requirePKCE came from `req.CodeChallengeMethod != ""`, which read like an
// opt-in. It could not actually be false - the field carries default:"S256"
// and bindings apply defaults - but the logic said a client's own request
// decided the policy, which is not a decision a client gets to make.
func TestARegisteringClientCannotOptOutOfPKCE(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid"}))

	// No code_challenge_method, exactly as a client wanting to skip PKCE
	// would send it - and with no defaults applied, since this calls the
	// handler directly rather than going through the binding.
	reg, err := client.RegisterClient(ctx, &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scope:                   "openid",
	})
	if err != nil {
		t.Fatal(err)
	}

	stored, err := mockDB.Clients.GetByClientID(ctx, reg.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, stored.RequirePKCE, "the client registered itself out of PKCE")

	assert.ErrorIs(t, authorizeNoPKCE(t, client, reg.ClientID), ErrInvalidRequest)
}
