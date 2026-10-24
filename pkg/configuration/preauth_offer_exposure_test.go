package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preAuthOfferCfg is a deployment with one datastore scope, described by
// the two things this guard reads: how a user authenticates for it, and
// whether an offer may be minted for it anyway.
func preAuthOfferCfg(authProvider string, allow bool) *model.Cfg {
	return &model.Cfg{APIGW: &model.APIGW{
		DataSources: model.DataSources{
			Datastore: model.DatastoreConfig{
				Scopes: map[string]model.DatastoreScope{
					"diploma": {AuthProvider: authProvider, AllowPreAuthOffer: allow},
				},
			},
		},
	}}
}

// withOIDC is the configuration under which the flag is permitted: an
// authenticated principal actually reaches the mint endpoint.
func withOIDC(cfg *model.Cfg) *model.Cfg {
	cfg.APIGW.APIServer.APIAuth.OIDC.Enable = true
	return cfg
}

// allow_preauth_offer removes the second gate on
// /api/v1/datastore/preauth_offer for a scope that is otherwise
// login-gated. Where that endpoint has no authenticated principal in
// front of it, the flag is a login bypass: the credential the scope gates
// behind a login becomes mintable by anyone who can reach the port.
func TestPreAuthOfferExposureRefusesAnUnauthenticatedDeployment(t *testing.T) {
	err := checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderOIDC, true), "apigw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow_preauth_offer")
	assert.Contains(t, err.Error(), "api_auth")
	assert.Contains(t, err.Error(), "diploma", "the message must name the scope the operator has to fix")
}

// The admin session is an alternative to a Bearer token, not a second
// check on top of it: with the admin UI on and OIDC off, /ui/login grants
// an anonymous session and SessionOrAPIAuth accepts it INSTEAD of falling
// through to the Bearer middleware. A JWKS configuration says nothing
// about that.
func TestPreAuthOfferExposureRefusesTheAnonymousAdminSession(t *testing.T) {
	cfg := preAuthOfferCfg(model.AuthProviderOIDC, true)
	cfg.APIGW.APIServer.APIAuth.JWKS.Enable = true
	cfg.APIGW.AdminUIEnable = true

	err := checkPreAuthOfferExposure(cfg, "apigw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin_ui_enable")
	assert.Contains(t, err.Error(), "oidc")
}

func TestPreAuthOfferExposureAcceptsWhatItShould(t *testing.T) {
	t.Run("OIDC configured", func(t *testing.T) {
		assert.NoError(t, checkPreAuthOfferExposure(withOIDC(preAuthOfferCfg(model.AuthProviderOIDC, true)), "apigw"))
	})

	t.Run("JWKS alone, with the admin UI off", func(t *testing.T) {
		cfg := preAuthOfferCfg(model.AuthProviderOIDC, true)
		cfg.APIGW.APIServer.APIAuth.JWKS.Enable = true
		assert.NoError(t, checkPreAuthOfferExposure(cfg, "apigw"))
	})

	// A scope that has no other way to be issued bypasses nothing, and
	// this is the behaviour the endpoint already had. It must not start
	// requiring API authentication now.
	t.Run("a real preauth scope, with no API authentication at all", func(t *testing.T) {
		assert.NoError(t, checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderPreAuth, false), "apigw"))
	})

	t.Run("a login-gated scope without the flag", func(t *testing.T) {
		assert.NoError(t, checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderOIDC, false), "apigw"))
	})

	// The flag on a scope that is already preauth says nothing new, so it
	// carries no exposure either.
	t.Run("the flag on an already-preauth scope", func(t *testing.T) {
		assert.NoError(t, checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderPreAuth, true), "apigw"))
	})

	t.Run("a service that is not the apigw", func(t *testing.T) {
		assert.NoError(t, checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderOIDC, true), "verifier"))
	})
}

// The operator page quotes both refusals. A quoted error message is the
// part of a document that goes stale silently: the text drifts, the page
// still reads plausibly, and the operator searching for the message they
// actually got finds nothing.
func TestTheOperatorPageQuotesTheRefusalsThisCodeProduces(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "issuer", "PREAUTHORIZED_OFFERS.md"))
	require.NoError(t, err)

	noBearer := checkPreAuthOfferExposure(preAuthOfferCfg(model.AuthProviderOIDC, true), "apigw")
	require.Error(t, noBearer)

	adminUI := preAuthOfferCfg(model.AuthProviderOIDC, true)
	adminUI.APIGW.APIServer.APIAuth.JWKS.Enable = true
	adminUI.APIGW.AdminUIEnable = true
	anonymousSession := checkPreAuthOfferExposure(adminUI, "apigw")
	require.Error(t, anonymousSession)

	// The opening clause of each, which is what an operator would paste
	// into a search box. Matching the whole message would pin the line
	// wrapping of a document rather than its content.
	for _, quoted := range []string{
		"apigw.data_sources.datastore.scopes sets allow_preauth_offer on login-gated",
		"anyone who can reach the port may call it",
		"Configure oidc, or turn the admin UI off",
	} {
		assert.Containsf(t, string(page), quoted,
			"the page no longer quotes %q, which this code still produces", quoted)
	}

	for _, produced := range []struct {
		err   error
		match string
	}{
		{noBearer, "anyone who can reach the port may call it"},
		{anonymousSession, "Configure oidc, or turn the admin UI off"},
	} {
		assert.Containsf(t, produced.err.Error(), produced.match,
			"the page quotes %q but the code no longer says it", produced.match)
	}
}
