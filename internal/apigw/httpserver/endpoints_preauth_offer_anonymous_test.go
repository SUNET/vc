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
func TestEndpointDatastorePreAuthOffer_RefusesAnAnonymousAdminSession(t *testing.T) {
	ctx := t.Context()

	log, err := logger.New("preauth-offer-anonymous-test", t.TempDir(), true)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "preauth-offer-anonymous-test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
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

	offer := func(subject string) *httptest.ResponseRecorder {
		login := httptest.NewRecorder()
		engine.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?subject="+subject, nil))

		body := `{"scope":"diploma","authentic_source":"source","document_id":"doc"}`
		req := httptest.NewRequest(http.MethodPost, "/datastore/preauth-offer", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range login.Result().Cookies() {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}

	w := offer(anonymousAdminSubject)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Nil(t, api.seen, "an anonymous session must not reach DatastorePreAuthOffer")

	api.seen = nil
	w = offer("alice")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotNil(t, api.seen, "an authenticated session must still be served")
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
