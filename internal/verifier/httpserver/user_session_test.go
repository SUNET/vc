package httpserver

import (
	"net/http"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidc_provider.session_duration is the lifetime of the OP's session with
// the end user. The verifier_user_session cookie was pinned at 900 seconds
// whatever an operator configured, and the key was read nowhere in the
// codebase (SUNET/vc#756).
func TestUserSessionCookieHonoursSessionDuration(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.Outbound.OIDCProvider = &model.OIDCOP{SessionDuration: 7200}

	assert.Equal(t, 7200, userSessionMaxAge(cfg))

	// ... and the options the constructor actually installs, not just the
	// helper - a literal put back in userSessionOptions leaves the helper
	// correct and unused.
	options, err := userSessionOptions(cfg)
	require.NoError(t, err)
	assert.Equal(t, 7200, options.MaxAge)
}

// The options stay otherwise as they were: HttpOnly, lax, and Secure only
// behind TLS.
func TestUserSessionCookieKeepsItsOtherOptions(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}

	plain, err := userSessionOptions(cfg)
	require.NoError(t, err)
	assert.True(t, plain.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, plain.SameSite)
	assert.Equal(t, "/", plain.Path)
	assert.Empty(t, plain.Domain)
	assert.False(t, plain.Secure)

	cfg.Verifier.APIServer.TLS.Enable = true
	secured, err := userSessionOptions(cfg)
	require.NoError(t, err)
	assert.True(t, secured.Secure)
}

// The documented default is 3600, so a deployment that never touched the key
// gets the hour its configuration has always claimed - not the 900 seconds
// the cookie was hardcoded to.
func TestUserSessionCookieTakesTheConfiguredDefault(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.Outbound.OIDCProvider = &model.OIDCOP{}
	require.NoError(t, defaults.Set(cfg.Verifier.Outbound.OIDCProvider))

	assert.Equal(t, 3600, userSessionMaxAge(cfg))
}

// With nothing to read, the cookie must still get a finite lifetime rather
// than 0 - which the session store reads as "expire with the browser
// session", not as the default.
func TestUserSessionCookieWithNothingConfigured(t *testing.T) {
	withProvider := &model.Cfg{Verifier: &model.Verifier{}}

	for name, cfg := range map[string]*model.Cfg{
		"no verifier section":    {},
		"no oidc_provider":       withProvider,
		"session_duration unset": {Verifier: &model.Verifier{Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{}}}},
	} {
		t.Run(name, func(t *testing.T) {
			got := userSessionMaxAge(cfg)
			assert.NotZero(t, got, "a zero MaxAge is a browser-session cookie, not the default")
			assert.Equal(t, defaultUserSessionMaxAge, got)
		})
	}
}

// An embedded presentation request lives on a page the verifier does not
// serve, so the session cookie has to survive a cross-site fetch. Both keys
// reach the cookie through the verifier's own constructor, not just through
// the shared helper.
func TestUserSessionCookieTakesTheConfiguredCrossSiteAttributes(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.APIServer.TrustProxyTLS = true
	cfg.Verifier.APIServer.SessionCookie = &model.SessionCookie{
		SameSite: "none",
		Domain:   ".example.com",
	}

	got, err := userSessionOptions(cfg)
	require.NoError(t, err)

	assert.Equal(t, http.SameSiteNoneMode, got.SameSite)
	assert.Equal(t, ".example.com", got.Domain)
	assert.True(t, got.Secure, "SameSite=None is only stored on a Secure cookie")
}

// trust_proxy_tls documents itself as forcing Secure on session cookies, and
// the apigw honoured it while the verifier read only tls.enable - so a
// verifier behind a TLS-terminating proxy served its session cookie without
// Secure.
func TestUserSessionCookieHonoursTrustProxyTLS(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.APIServer.TrustProxyTLS = true

	got, err := userSessionOptions(cfg)
	require.NoError(t, err)
	assert.True(t, got.Secure)
}

// A cookie no browser stores stops the verifier at startup, rather than
// leaving every session to fail with nothing naming the cause.
func TestUserSessionCookieRefusesCrossSiteWithoutSecure(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.APIServer.SessionCookie = &model.SessionCookie{SameSite: "none"}

	_, err := userSessionOptions(cfg)
	require.Error(t, err)
}
