package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/internal/apigw/staticembed"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBrandingMiddleware returns a gin.HandlerFunc that intercepts
// /static/logo.png and /static/favicon.png when custom paths are configured,
// mirroring the CustomBranding middleware from httphelpers.
// This is intentionally duplicated here to test the registration ORDER
// (middleware before StaticFS) without pulling in the full httphelpers.Client.
func newTestBrandingMiddleware(branding model.Branding) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.URL.Path {
		case "/static/logo.png":
			if branding.LogoPath != "" {
				c.File(branding.LogoPath)
				c.Abort()
				return
			}
		case "/static/favicon.png":
			if branding.FaviconPath != "" {
				c.File(branding.FaviconPath)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// TestBrandingMiddlewareOrder_CorrectOrder verifies that when CustomBranding
// middleware is registered BEFORE StaticFS, custom files take priority over
// embedded defaults. This is a regression test for #361.
func TestBrandingMiddlewareOrder_CorrectOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("custom-logo"), 0644)) //#nosec G306

	branding := model.Branding{LogoPath: logoPath}

	// Correct order: middleware first, then static files (matches the fix)
	engine := gin.New()
	engine.Use(newTestBrandingMiddleware(branding))
	engine.StaticFS("/static", http.FS(staticembed.FS))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/static/logo.png", nil)
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "custom-logo", w.Body.String(), "custom logo should override embedded default")
}

// TestBrandingMiddlewareOrder_WrongOrder demonstrates the bug from #361:
// when StaticFS is registered BEFORE the branding middleware, the middleware
// is not in the handler chain and the embedded default is served instead.
func TestBrandingMiddlewareOrder_WrongOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("custom-logo"), 0644)) //#nosec G306

	branding := model.Branding{LogoPath: logoPath}

	// Wrong order: static files first, then middleware (the pre-fix bug)
	engine := gin.New()
	engine.StaticFS("/static", http.FS(staticembed.FS))
	engine.Use(newTestBrandingMiddleware(branding))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/static/logo.png", nil)
	engine.ServeHTTP(w, req)

	// With wrong order, the embedded default is served — NOT the custom logo.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, "custom-logo", w.Body.String(), "wrong order should serve embedded default, not custom logo")
}
