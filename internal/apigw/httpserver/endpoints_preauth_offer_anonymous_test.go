package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// offerAPI records whether the handler was reached at all, which is the
// assertion that matters: a refusal that still ran the offer is not a refusal.
type offerAPI struct {
	unimplementedApiv1
	seen *apiv1.DatastorePreAuthOfferRequest
}

func (o *offerAPI) DatastorePreAuthOffer(_ context.Context, r *apiv1.DatastorePreAuthOfferRequest) (*apiv1.DatastorePreAuthOfferReply, error) {
	o.seen = r
	return &apiv1.DatastorePreAuthOfferReply{}, nil
}

// An anonymous admin session issued before the configuration changed stays
// valid for its lifetime - session keys persist across restarts in HA - and
// SessionOrAPIAuth accepts it in place of a bearer token. checkPreAuthOfferExposure
// refuses the configuration, not the cookies already handed out, so enabling
// OIDC (or disabling the UI with JWKS enabled) lets startup pass while those
// cookies still work. With allow_preauth_offer in play, what they can mint now
// includes the login-gated scopes, so the endpoint has to refuse them itself.
func TestEndpointDatastorePreAuthOffer_AnonymousSessionAndScopeCollisions(t *testing.T) {
	ctx := t.Context()

	log, err := logger.New("preauth-offer-anonymous-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "preauth-offer-anonymous-test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			DataSources: model.DataSources{
				Datastore: model.DatastoreConfig{
					Scopes: map[string]model.DatastoreScope{
						// No login of its own: an anonymous admin session is
						// the supported way to offer this one.
						"twin": {AuthProvider: model.AuthProviderPreAuth},
						// Login-gated, opened to offers for an AUTHENTICATED
						// operator by the flag. Not for an anonymous one.
						"diploma": {AuthProvider: model.AuthProviderOIDC, AllowPreAuthOffer: true},
					},
				},
			},
		},
	}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	api := &offerAPI{}
	s := &Service{cfg: cfg, log: log.New("httpserver"), apiv1: api, tracer: tracer, httpHelpers: helpers}

	store := cookie.NewStore([]byte("12345678901234567890123456789012"), []byte("1234567890123456"))
	engine := gin.New()
	engine.Use(sessions.Sessions("admin_session", store))
	engine.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", c.Query("subject"))
		_ = session.Save()
	})
	helpers.Server.RegEndpoint(ctx, engine.Group(""), http.MethodPost, "datastore/preauth-offer", http.StatusOK, s.endpointDatastorePreAuthOffer)

	offer := func(subject, body string, headers ...string) *httptest.ResponseRecorder {
		login := httptest.NewRecorder()
		engine.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?subject="+subject, nil))

		req := httptest.NewRequest(http.MethodPost, "/datastore/preauth-offer", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		for _, c := range login.Result().Cookies() {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}

	const (
		twinBody    = `{"scope":"twin","authentic_source":"SUNET","document_id":"doc-1"}`
		diplomaBody = `{"scope":"diploma","authentic_source":"SUNET","document_id":"doc-1"}`
	)

	// The workflow that must survive: admin UI on, no OIDC, a preauth twin.
	// /ui/login grants the anonymous session on purpose, and
	// checkPreAuthOfferExposure lets that configuration start.
	t.Run("an anonymous session may still offer a genuine preauth scope", func(t *testing.T) {
		api.seen = nil
		w := offer(anonymousAdminSubject, twinBody)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, api.seen)
		assert.Equal(t, "twin", api.seen.Scope)
	})

	t.Run("an anonymous session may not offer a flagged login-gated scope", func(t *testing.T) {
		api.seen = nil
		w := offer(anonymousAdminSubject, diplomaBody)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.Nil(t, api.seen, "an anonymous session must not reach DatastorePreAuthOffer for a login-gated scope")
	})

	t.Run("an authenticated session may offer the flagged scope", func(t *testing.T) {
		api.seen = nil
		w := offer("alice", diplomaBody)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, api.seen)
		assert.Equal(t, "diploma", api.seen.Scope)
	})

	// The authorization middleware reads the exact key "scope" and would see
	// the twin; encoding/json takes the LAST member case-insensitively and
	// would bind "diploma". Authorized for one scope, acted on for another.
	t.Run("a body naming the scope twice is refused, not resolved", func(t *testing.T) {
		api.seen = nil
		w := offer("alice", `{"scope":"twin","Scope":"diploma","authentic_source":"SUNET","document_id":"doc-1"}`)
		assert.NotEqual(t, http.StatusOK, w.Code, "an ambiguous body must not be acted on: %s", w.Body.String())
		assert.Nil(t, api.seen, "neither reading may reach the handler")
	})

	// SessionOrAPIAuth finds no resource pair in "{}" and skips the SPOCP check;
	// headers must not be able to fill in the fields it never looked at.
	t.Run("scope, source and document cannot come from headers", func(t *testing.T) {
		api.seen = nil
		offer("alice", `{}`,
			"Scope", "diploma", "AuthenticSource", "SUNET", "DocumentID", "doc-1")
		// This harness installs no gin validator, so an empty request may reach the handler.
		if api.seen != nil {
			assert.Empty(t, api.seen.Scope, "a Scope header must not set the scope")
			assert.Empty(t, api.seen.AuthenticSource, "an AuthenticSource header must not set the source")
			assert.Empty(t, api.seen.DocumentID, "a DocumentID header must not set the document")
		}
	})
}

// The admin UI hides its Offer action for any scope missing from this list,
// and admin.js refuses such a scope locally before a request is made. Listing
// only the preauth twins would therefore remove the UI workflow for exactly
// the scopes allow_preauth_offer exists to serve, even though the handler
// accepts them - requirePreAuthScope admits both, so this must too.
//
// Through the real endpoint, because the predicate is the thing under test: a
// test that recomputed it here would pass with the endpoint still wrong.
func TestAdminStatusListsScopesFlaggedForPreAuthOffers(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			DataSources: model.DataSources{
				Datastore: model.DatastoreConfig{
					Scopes: map[string]model.DatastoreScope{
						"twin":       {AuthProvider: model.AuthProviderPreAuth},
						"diploma":    {AuthProvider: model.AuthProviderOIDC, AllowPreAuthOffer: true},
						"login_only": {AuthProvider: model.AuthProviderOIDC},
					},
				},
			},
		},
	}
	rules := []string{
		`(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source *)(scope *))`,
	}

	engine := testSetupAdminStatus(t, "alice@sunet.se", rules, cfg, &adminStatusMock{authenticSources: []string{"SUNET"}})
	result := getStatus(t, engine, loginAndGetCookies(t, engine))

	raw, ok := result["preauth_scopes"].([]any)
	require.True(t, ok, "preauth_scopes should be a list, got %T", result["preauth_scopes"])
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		got = append(got, v.(string))
	}

	assert.ElementsMatch(t, []string{"twin", "diploma"}, got)
	assert.NotContains(t, got, "login_only",
		"a scope with neither the twin nor the flag must not get the Offer action")
}
