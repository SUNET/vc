package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupAPI captures the request the handler builds, which is the only place
// the holder's language preference can enter apiv1.
type lookupAPI struct {
	unimplementedApiv1
	got *vcclient.UserLookupRequest
}

func (a *lookupAPI) GetVCTMFromScope(context.Context, *apiv1.GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	return &sdjwtvc.VCTM{VCT: "urn:example:pid"}, nil
}

func (a *lookupAPI) UserLookup(_ context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	a.got = req

	return &vcclient.UserLookupReply{RedirectURL: "https://wallet.example/cb?code=abc"}, nil
}

// userLookupEngine registers the real route behind the same session middleware
// service.go puts it behind, seeding the session keys the handler reads.
func userLookupEngine(t *testing.T, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	rg.Use(helpers.Middleware.UserSession("test_session",
		"0123456789abcdef0123456789abcdef", "0123456789abcdef", sessions.Options{Path: "/"}))
	rg.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("scope", "pid")
		session.Set("request_uri", "urn:ietf:params:oauth:request_uri:abc")
		session.Set("auth_provider", model.AuthProviderOpenID4VP)
		session.Set("response_code", "response-code-1")
		_ = session.Save()
		c.Next()
	})
	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, "user/lookup", http.StatusOK, s.endpointUserLookup)

	return engine
}

// The consent page names the credential from its type metadata, which may
// carry one display entry per language. apiv1 cannot see the request, so the
// handler has to carry Accept-Language across; without this the page picked
// whichever entry the metadata listed first.
func TestUserLookupCarriesTheHolderLanguagePreference(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "the browser's ordered preference reaches apiv1",
			header: "sv-SE,sv;q=0.9,en-US;q=0.8",
			want:   []string{"sv-se", "sv", "en-us"},
		},
		{
			name:   "a request with no Accept-Language carries none",
			header: "",
			want:   []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &lookupAPI{}
			engine := userLookupEngine(t, api)

			req := httptest.NewRequest(http.MethodGet, "/user/lookup", nil)
			if tc.header != "" {
				req.Header.Set("Accept-Language", tc.header)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			require.NotNil(t, api.got, "UserLookup was never called")
			assert.Equal(t, tc.want, api.got.Locales)
		})
	}
}
