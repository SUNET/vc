package apiv1

import (
	"testing"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr(b bool) *bool { return &b }

// cfgWithPKCE is a Cfg whose OP carries this policy.
func cfgWithPKCE(requirePKCE *bool) *model.Cfg {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.Outbound.OIDCProvider = &model.OIDCOP{RequirePKCE: requirePKCE}
	return cfg
}

// clientWith is a Client carrying only the config the policy reads.
func clientWith(requirePKCE *bool) *Client {
	return &Client{cfg: cfgWithPKCE(requirePKCE)}
}

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
		assert.True(t, clientWith(ptr(false)).pkceRequired(client, false),
			"a public client with RequirePKCE=%v was let through", requirePKCE)
	}
}

// A confidential client follows its resolved flag, so an operator can
// exempt one that cannot send a code_challenge yet.
func TestPKCEFollowsTheFlagForAConfidentialClient(t *testing.T) {
	// Pinned on the record: required whatever the policy says.
	pinned := &db.Client{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: true}
	assert.True(t, clientWith(ptr(true)).pkceRequired(pinned, false))
	assert.True(t, clientWith(ptr(false)).pkceRequired(pinned, false))

	// Unpinned: the OP's policy decides, and it defaults to true.
	unpinned := &db.Client{TokenEndpointAuthMethod: "client_secret_basic"}
	assert.True(t, clientWith(nil).pkceRequired(unpinned, false), "the default is to require PKCE")
	assert.True(t, clientWith(ptr(true)).pkceRequired(unpinned, false))
	assert.False(t, clientWith(ptr(false)).pkceRequired(unpinned, false))
}

// Static clients had no PKCE at all and no way to ask for it: the db.Client
// built from YAML never set the flag (SUNET/vc#757).
func TestStaticClientPKCEPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		static model.StaticOIDCClient
		op     *model.Cfg
		want   bool
	}{
		{
			name:   "required by default",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     cfgWithPKCE(nil),
			want:   true,
		},
		{
			name:   "required when the policy says so",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     cfgWithPKCE(ptr(true)),
			want:   true,
		},
		{
			name:   "the policy can exempt a confidential client",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     cfgWithPKCE(ptr(false)),
			want:   false,
		},
		{
			name:   "one client can be exempted without relaxing the policy",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: ptr(false)},
			op:     cfgWithPKCE(ptr(true)),
			want:   false,
		},
		{
			name:   "one client can be held to it while the policy is relaxed",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: ptr(true)},
			op:     cfgWithPKCE(ptr(false)),
			want:   true,
		},
		{
			name:   "a public client is required even with the policy off",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "none"},
			op:     cfgWithPKCE(ptr(false)),
			want:   true,
		},
		{
			name:   "a public client is required even when exempted by name",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "none", RequirePKCE: ptr(false)},
			op:     cfgWithPKCE(ptr(false)),
			want:   true,
		},
		{
			name:   "no oidc_provider section is still required",
			static: model.StaticOIDCClient{TokenEndpointAuthMethod: "client_secret_basic"},
			op:     &model.Cfg{Verifier: &model.Verifier{}},
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

// pkceTestClient is a verifier configured for the openid scope, with the
// OP-wide policy set to opPolicy (nil leaves the default).
func pkceTestClient(t *testing.T, opPolicy *bool) (*Client, *MockDBService) {
	t.Helper()

	client, mockDB := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.RequirePKCE = opPolicy
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid"}))
	return client, mockDB
}

// withStaticClient configures one static client and returns its id.
func withStaticClient(t *testing.T, client *Client, clientID, authMethod string, requirePKCE *bool) string {
	t.Helper()

	secret := "secret"
	if authMethod == tokenEndpointAuthNone {
		secret = ""
	}
	client.cfg.Verifier.Outbound.OIDCProvider.StaticClients = []model.StaticOIDCClient{{
		ClientID:                clientID,
		ClientSecret:            secret,
		RedirectURIs:            []string{"https://example.com/callback"},
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: authMethod,
		RequirePKCE:             requirePKCE,
	}}
	return clientID
}

// registerDynamicClient registers a client the way one that wants no PKCE
// would: no code_challenge_method, and no defaults applied, since this
// calls the handler directly rather than going through the binding.
func registerDynamicClient(t *testing.T, client *Client, authMethod string) string {
	t.Helper()

	reg, err := client.RegisterClient(t.Context(), &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scope:                   "openid",
	})
	require.NoError(t, err)
	return reg.ClientID
}

// A static client reaching /authorize without a code_challenge is refused.
//
// It was not: getClientByID built its db.Client without RequirePKCE, so the
// flag was false and the check at handler_oidc.go never fired - while
// discovery advertised code_challenge_methods_supported (SUNET/vc#757).
func TestAuthorizeRefusesAStaticClientWithoutPKCE(t *testing.T) {
	client, _ := pkceTestClient(t, nil)
	id := withStaticClient(t, client, "static-client", "client_secret_basic", nil)

	assert.ErrorIs(t, authorizeNoPKCE(t, client, id), ErrInvalidRequest)
}

// ... and an operator can still exempt one, which is what makes the test
// above a policy test rather than a constant.
func TestAuthorizeAllowsAnExemptedStaticClientWithoutPKCE(t *testing.T) {
	client, _ := pkceTestClient(t, nil)
	id := withStaticClient(t, client, "legacy-client", "client_secret_basic", ptr(false))

	assert.NoError(t, authorizeNoPKCE(t, client, id))
}

// A public static client cannot be exempted, however the config is written.
func TestAuthorizeRefusesAPublicStaticClientEvenWhenExempted(t *testing.T) {
	client, _ := pkceTestClient(t, ptr(false))
	id := withStaticClient(t, client, "public-client", tokenEndpointAuthNone, ptr(false))

	assert.ErrorIs(t, authorizeNoPKCE(t, client, id), ErrInvalidRequest)
}

// A dynamically registered client cannot register itself out of PKCE.
//
// requirePKCE came from `req.CodeChallengeMethod != ""`, which read like an
// opt-in. It could not actually be false - the field carries default:"S256"
// and bindings apply defaults - but the logic said a client's own request
// decided the policy, which is not a decision a client gets to make.
func TestARegisteringClientCannotOptOutOfPKCE(t *testing.T) {
	client, mockDB := pkceTestClient(t, nil)
	id := registerDynamicClient(t, client, "client_secret_basic")

	// The record carries no policy the client chose. RequirePKCE can only
	// ever pin PKCE on, and registration does not set it either way - which
	// is what lets the OP's require_pkce reach dynamic clients too.
	stored, err := mockDB.Clients.GetByClientID(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, stored.RequirePKCE, "registration stored a policy of the client's choosing")

	// ... and the client is required all the same, by the OP's default.
	assert.ErrorIs(t, authorizeNoPKCE(t, client, id), ErrInvalidRequest)
}

// The OP-wide override reaches dynamic clients, not only the ones written
// in YAML. Registration used to pin RequirePKCE true, so require_pkce:
// false exempted static confidential clients while otherwise identical
// dynamic ones stayed required - policy depending on how the client was
// created, which is the thing SUNET/vc#757 is about.
func TestTheOPOverrideReachesDynamicClients(t *testing.T) {
	client, _ := pkceTestClient(t, ptr(false))
	id := registerDynamicClient(t, client, "client_secret_basic")

	assert.NoError(t, authorizeNoPKCE(t, client, id),
		"require_pkce: false did not reach a dynamically registered client")
}

// A public client registered dynamically is still required, override or
// not.
func TestTheOPOverrideDoesNotReachAPublicDynamicClient(t *testing.T) {
	client, _ := pkceTestClient(t, ptr(false))
	id := registerDynamicClient(t, client, tokenEndpointAuthNone)

	assert.ErrorIs(t, authorizeNoPKCE(t, client, id), ErrInvalidRequest)
}

// A code_challenge the OP cannot verify is refused.
//
// CreateCodeChallenge returns the verifier unchanged for every method but
// S256, so an unrecognised method - and an OMITTED one, which RFC 7636 4.3
// defines as "plain" - was silently downgraded to plain: the challenge IS
// the verifier, and anyone holding the code can redeem it. Discovery has
// only ever advertised ["S256"].
func TestAuthorizeRefusesAChallengeItCannotVerify(t *testing.T) {
	client, _ := pkceTestClient(t, nil)
	id := withStaticClient(t, client, "pkce-client", "client_secret_basic", nil)

	authorize := func(method string) error {
		_, err := client.Authorize(t.Context(), &AuthorizeRequest{
			ResponseType:        "code",
			ClientID:            id,
			RedirectURI:         "https://example.com/callback",
			Scope:               "openid",
			State:               "state",
			Nonce:               "nonce",
			CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			CodeChallengeMethod: method,
		})
		return err
	}

	for _, method := range []string{"plain", "", "s256", "S512", "nonsense"} {
		t.Run("method="+method, func(t *testing.T) {
			assert.ErrorIs(t, authorize(method), ErrInvalidRequest)
		})
	}

	assert.NoError(t, authorize("S256"), "S256 is the method the OP advertises")
}
