package httphelpers

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestIsJSONOnlyPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// OIDC/OAuth2 endpoints
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

		// REST API surface is JSON-only too
		{"/api/v1/users", true},
		{"/api/v1/datastore", true},

		// Browser-facing paths are not JSON-only
		{"/dashboard", false},
		{"/admin", false},
		{"/health", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isJSONOnlyPath(tt.path); got != tt.want {
				t.Errorf("isJSONOnlyPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPrefersHTML(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"typical browser", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8", true},
		{"html only", "text/html", true},
		{"html with explicit q=1", "text/html;q=1.0", true},
		{"html disabled by q=0", "text/html;q=0", false},
		{"html ranked below json", "application/json, text/html;q=0.5", false},
		{"html equal to json wins", "application/json;q=0.5, text/html;q=0.5", true},
		{"json only", "application/json", false},
		{"wildcard only (curl)", "*/*", false},
		{"empty header", "", false},
		{"substring false positive", "application/x-text/html", false},
		{"malformed q defaults to 1", "text/html;q=notanumber", true},
		{"whitespace and casing", "  TEXT/HTML ;  q=0.9  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := prefersHTML(tt.accept); got != tt.want {
				t.Errorf("prefersHTML(%q) = %v, want %v", tt.accept, got, tt.want)
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
		{"browser on API route stays JSON", "/api/v1/datastore", "text/html,*/*;q=0.8", false, "something_failed"},
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
	require.False(t, r.wantsErrorHTML(newCtx("/api/v1/datastore", "text/html"), 500), "API routes stay JSON")
}

func TestErrorPageLogo(t *testing.T) {
	embedded := errorPageLogo(model.Branding{})
	require.True(t, strings.HasPrefix(string(embedded), "data:image/png;base64,"))

	custom := []byte("custom-logo-bytes")
	path := filepath.Join(t.TempDir(), "logo.png")
	require.NoError(t, os.WriteFile(path, custom, 0o600))

	got := errorPageLogo(model.Branding{LogoPath: path})
	want := "data:image/png;base64," + base64.StdEncoding.EncodeToString(custom)
	require.Equal(t, want, string(got), "a readable logo_path overrides the embedded logo")

	// An unreadable override falls back to the embedded logo rather than failing.
	require.Equal(t, embedded, errorPageLogo(model.Branding{LogoPath: "/no/such/logo.png"}))
}
