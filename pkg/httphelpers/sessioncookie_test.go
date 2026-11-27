package httphelpers

import (
	"net/http"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Nothing configured is the cookie both services already served: host-only,
// lax, HttpOnly, and not Secure without TLS.
func TestSessionCookieDefaultsToSameOriginOnly(t *testing.T) {
	got, err := SessionCookieOptions(model.APIServer{}, 900)
	require.NoError(t, err)

	assert.Equal(t, "/", got.Path)
	assert.Empty(t, got.Domain, "a host-only cookie goes back only to the host that set it")
	assert.Equal(t, 900, got.MaxAge)
	assert.True(t, got.HttpOnly)
	assert.False(t, got.Secure)
	assert.Equal(t, http.SameSiteLaxMode, got.SameSite)
}

// trust_proxy_tls is how a deployment says the TLS it is reached over
// terminates in front of it. The apigw honoured it and the verifier did not,
// so a verifier behind a proxy served its session cookie without Secure -
// and SameSite=None, which needs Secure, could not be reached at all.
func TestSessionCookieSecureFollowsTheDeployment(t *testing.T) {
	for name, apiServer := range map[string]model.APIServer{
		"tls on this server": {TLS: model.TLS{Enable: true}},
		"tls in front":       {TrustProxyTLS: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := SessionCookieOptions(apiServer, 900)
			require.NoError(t, err)
			assert.True(t, got.Secure)
		})
	}
}

func TestSessionCookieSameSiteAndDomain(t *testing.T) {
	for name, tc := range map[string]struct {
		sameSite string
		want     http.SameSite
	}{
		"unset is lax": {"", http.SameSiteLaxMode},
		"lax":          {"lax", http.SameSiteLaxMode},
		"strict":       {"strict", http.SameSiteStrictMode},
		"none":         {"none", http.SameSiteNoneMode},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := SessionCookieOptions(model.APIServer{
				TrustProxyTLS: true,
				SessionCookie: &model.SessionCookie{SameSite: tc.sameSite, Domain: ".example.com"},
			}, 900)
			require.NoError(t, err)

			assert.Equal(t, tc.want, got.SameSite)
			assert.Equal(t, ".example.com", got.Domain)
		})
	}
}

// A browser silently drops a SameSite=None cookie that is not Secure. The
// flow it was configured for would then fail with no session and nothing in
// the logs naming the cookie, so the configuration is refused at startup
// instead.
func TestSessionCookieRefusesSameSiteNoneWithoutSecure(t *testing.T) {
	_, err := SessionCookieOptions(model.APIServer{
		SessionCookie: &model.SessionCookie{SameSite: "none"},
	}, 900)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust_proxy_tls")
}

// An unknown value is refused rather than quietly treated as lax, which
// would leave an operator who wrote "None" with a cookie no cross-site
// request carries and no reason given.
func TestSessionCookieRefusesAnUnknownSameSite(t *testing.T) {
	_, err := SessionCookieOptions(model.APIServer{
		SessionCookie: &model.SessionCookie{SameSite: "no-restriction"},
	}, 900)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-restriction")
}
