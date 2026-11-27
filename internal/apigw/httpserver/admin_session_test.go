package httpserver

import (
	"net/http"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func widenedCfg() *model.Cfg {
	cfg := &model.Cfg{APIGW: &model.APIGW{}}
	cfg.APIGW.APIServer.TrustProxyTLS = true
	cfg.APIGW.APIServer.SessionCookie = &model.SessionCookie{
		SameSite: "none",
		Domain:   ".example.com",
	}
	return cfg
}

// One options value used to back both oauth_user_session and admin_session,
// so configuring the end user's cookie for a cross-site flow would also have
// sent the administrator's cookie - a bearer credential for the whole API -
// to every sibling host the domain names, where it can be captured and
// replayed.
func TestAdminSessionIsNotWidenedByTheUserSessionConfiguration(t *testing.T) {
	cfg := widenedCfg()

	user, err := oauthUserSessionOptions(cfg)
	require.NoError(t, err)
	require.Equal(t, http.SameSiteNoneMode, user.SameSite, "the user cookie takes the configuration")
	require.Equal(t, ".example.com", user.Domain)

	admin, err := adminSessionOptions(cfg)
	require.NoError(t, err)
	assert.Equal(t, http.SameSiteLaxMode, admin.SameSite, "the admin cookie stays lax")
	assert.Empty(t, admin.Domain, "the admin cookie stays host-only")
}

// The deployment's TLS still reaches the admin cookie; only the operator's
// cross-site keys are dropped.
func TestAdminSessionStillFollowsTheDeployment(t *testing.T) {
	admin, err := adminSessionOptions(widenedCfg())
	require.NoError(t, err)

	assert.True(t, admin.Secure)
	assert.True(t, admin.HttpOnly)
	assert.Equal(t, "/", admin.Path)
}

// A cookie combination no browser stores still stops the apigw at startup,
// by the same path the verifier is stopped.
func TestAPIGWRefusesCrossSiteWithoutSecure(t *testing.T) {
	cfg := &model.Cfg{APIGW: &model.APIGW{}}
	cfg.APIGW.APIServer.SessionCookie = &model.SessionCookie{SameSite: "none"}

	_, err := oauthUserSessionOptions(cfg)
	require.Error(t, err)
}
