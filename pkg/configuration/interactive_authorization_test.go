package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iaCfg is a deployment with API authentication configured, which is what
// a deployment enabling Interactive Authorization has to be: enabling it
// exposes /api/v1/issuance/prepare. See iaCfgWithoutAPIAuth.
func iaCfg(enable, require bool) *model.Cfg {
	cfg := iaCfgWithoutAPIAuth(enable, require)
	cfg.APIGW.APIServer.APIAuth.OIDC.Enable = true
	return cfg
}

func iaCfgWithoutAPIAuth(enable, require bool) *model.Cfg {
	return &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		InteractiveAuthorization: model.InteractiveAuthorization{
			Enable:                          &enable,
			RequireInteractiveAuthorization: &require,
		},
	}}}
}

// A server cannot require a mechanism it does not offer. The metadata
// struct refuses the pair as well, but that refusal arrives at serving
// time with no operator watching; this one arrives at startup.
func TestCheckInteractiveAuthorization(t *testing.T) {
	t.Run("require without enable is refused", func(t *testing.T) {
		err := checkInteractiveAuthorization(iaCfg(false, true), "apigw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require_interactive_authorization")
		assert.Contains(t, err.Error(), "enable is false")
	})

	for _, tt := range []struct {
		name    string
		enable  bool
		require bool
	}{
		{name: "require with enable", enable: true, require: true},
		{name: "neither", enable: false, require: false},
		{name: "enable alone", enable: true, require: false},
	} {
		t.Run(tt.name+" is accepted", func(t *testing.T) {
			assert.NoError(t, checkInteractiveAuthorization(iaCfg(tt.enable, tt.require), "apigw"))
		})
	}

	// Enabling the mechanism exposes POST /api/v1/issuance/prepare, which
	// prepares an issuance for a Holder the CALLER names. With neither
	// Bearer mode configured the API-auth middleware is a pass-through, so
	// that is an open endpoint for minting credential offers against any
	// identity rule - the trusted-portal step the mechanism represents,
	// available to anyone who can reach the port.
	t.Run("enabling it without API authentication is refused", func(t *testing.T) {
		err := checkInteractiveAuthorization(iaCfgWithoutAPIAuth(true, false), "apigw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuance/prepare")
		assert.Contains(t, err.Error(), "api_auth")
	})

	t.Run("either Bearer mode is enough on its own", func(t *testing.T) {
		jwks := iaCfgWithoutAPIAuth(true, false)
		jwks.APIGW.APIServer.APIAuth.JWKS.Enable = true
		assert.NoError(t, checkInteractiveAuthorization(jwks, "apigw"))

		oidc := iaCfgWithoutAPIAuth(true, false)
		oidc.APIGW.APIServer.APIAuth.OIDC.Enable = true
		assert.NoError(t, checkInteractiveAuthorization(oidc, "apigw"))
	})

	// A Bearer mode is not enough when the admin session is an
	// ALTERNATIVE to it rather than a second check on top.
	//
	// /ui/login grants a session with admin_subject "anonymous" when no
	// OIDC is configured, and SessionOrAPIAuth accepts a session INSTEAD
	// of falling through to the Bearer middleware. So jwks enabled plus
	// the admin UI on still leaves preparation reachable by an anonymous
	// caller, and the jwks configuration says nothing about it.
	t.Run("the admin UI without OIDC is refused", func(t *testing.T) {
		cfg := iaCfgWithoutAPIAuth(true, false)
		cfg.APIGW.APIServer.APIAuth.JWKS.Enable = true
		cfg.APIGW.AdminUIEnable = true

		err := checkInteractiveAuthorization(cfg, "apigw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "anonymous session")
		assert.Contains(t, err.Error(), "admin_ui_enable")
	})

	t.Run("the admin UI with OIDC is accepted", func(t *testing.T) {
		cfg := iaCfgWithoutAPIAuth(true, false)
		cfg.APIGW.APIServer.APIAuth.OIDC.Enable = true
		cfg.APIGW.AdminUIEnable = true
		assert.NoError(t, checkInteractiveAuthorization(cfg, "apigw"))
	})

	t.Run("the admin UI off needs no OIDC", func(t *testing.T) {
		cfg := iaCfgWithoutAPIAuth(true, false)
		cfg.APIGW.APIServer.APIAuth.JWKS.Enable = true
		assert.NoError(t, checkInteractiveAuthorization(cfg, "apigw"))
	})

	// An admin session is not authentication for this purpose: it is
	// granted anonymously when OIDC is absent, so a check that accepted it
	// would pass for everyone.
	t.Run("a deployment with the mechanism off is unaffected", func(t *testing.T) {
		assert.NoError(t, checkInteractiveAuthorization(iaCfgWithoutAPIAuth(false, false), "apigw"))
	})

	t.Run("other services are unaffected", func(t *testing.T) {
		// Only apigw serves the Authorization Server metadata; the whole
		// APIGW block is nil on every other service's config by then.
		assert.NoError(t, checkInteractiveAuthorization(iaCfg(false, true), "verifier"))
		assert.NoError(t, checkInteractiveAuthorization(&model.Cfg{}, "apigw"))
	})
}
