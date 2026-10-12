package httphelpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestIsOIDCEndpoint(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Existing OIDC/OAuth2 endpoints
		{"/.well-known/openid-configuration", true},
		{"/op/jwks", true},
		{"/op/register", true},
		{"/op/token", true},
		{"/op/userinfo", true},
		{"/oidcrp/callback", true},
		{"/samlsp/acs", true},
		{"/op/par", true},

		// OID4VCI endpoints (issue #437)
		{"/nonce", true},
		{"/credential", true},
		{"/credential-offer/abc123", true},
		{"/deferred_credential", true},
		{"/notification", true},

		// Non-OIDC endpoints should return false
		{"/api/v1/users", false},
		{"/health", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isOIDCEndpoint(tt.path); got != tt.want {
				t.Errorf("isOIDCEndpoint(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// renderEngine builds an engine with one route that renders an error through
// Content, so a test can vary the request path and Accept header.
func renderEngine(t *testing.T, path string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	log, err := logger.New("rendertest", t.TempDir(), false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	client, err := New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("req_id", "req-123") })
	engine.GET(path, func(c *gin.Context) {
		client.Rendering.Content(ctx, c, http.StatusInternalServerError,
			gin.H{"error": helpers.NewError("something_failed")})
	})
	return engine
}

func TestContent_ErrorRendering(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		accept      string
		wantHTML    bool
		wantContain string
	}{
		{"browser non-API gets HTML", "/dashboard", "text/html,application/xhtml+xml,*/*;q=0.8", true, "req-123"},
		{"browser on OIDC endpoint stays JSON", "/token", "text/html,*/*;q=0.8", false, "something_failed"},
		{"json client stays JSON", "/dashboard", "application/json", false, "something_failed"},
		{"curl wildcard stays JSON", "/dashboard", "*/*", false, "something_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := renderEngine(t, tt.path)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Accept", tt.accept)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equal(t, http.StatusInternalServerError, w.Code)
			ct := w.Header().Get("Content-Type")
			if tt.wantHTML {
				require.Contains(t, ct, "text/html")
				require.Contains(t, w.Body.String(), "Internal Server Error")
			} else {
				require.Contains(t, ct, "application/json")
			}
			require.Contains(t, w.Body.String(), tt.wantContain)
		})
	}
}

func TestWantsErrorHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := &renderingHandler{}

	newCtx := func(path, accept string) *gin.Context {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", accept)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = req
		return c
	}

	require.True(t, r.wantsErrorHTML(newCtx("/dashboard", "text/html"), 500))
	require.True(t, r.wantsErrorHTML(newCtx("/dashboard", "text/html"), 404))
	require.False(t, r.wantsErrorHTML(newCtx("/dashboard", "text/html"), 200), "success is never an error page")
	require.False(t, r.wantsErrorHTML(newCtx("/dashboard", "*/*"), 500), "wildcard is not an explicit html ask")
	require.False(t, r.wantsErrorHTML(newCtx("/dashboard", "application/json"), 500))
	require.False(t, r.wantsErrorHTML(newCtx("/token", "text/html"), 500), "OIDC endpoints stay JSON")
}
