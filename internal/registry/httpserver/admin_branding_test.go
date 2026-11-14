package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/internal/registry/httpserver/staticembed"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin GUI mounts its assets at /admin/static rather than /static, and
// its pages reference /admin/static/logo.png (admin_templates.go). While
// CustomBranding matched /static alone, this was the one page in the product
// that stayed on the built-in logo whatever common.branding configured.
//
// Built the way New builds it - the real middleware, the real embedded assets,
// the real mount path, and the middleware registered before the static route
// so that it is in that route's handler chain (gin snapshots the chain at
// registration time; see SUNET/vc#361).
func TestAdminStaticAssetsHonorCustomBranding(t *testing.T) {
	s := setupTestService(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	faviconPath := filepath.Join(dir, "favicon.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("operator-logo"), 0o644))       //#nosec G306
	require.NoError(t, os.WriteFile(faviconPath, []byte("operator-favicon"), 0o644)) //#nosec G306

	engine := gin.New()
	engine.Use(s.httpHelpers.Middleware.CustomBranding(model.Branding{
		LogoPath:    logoPath,
		FaviconPath: faviconPath,
	}))
	engine.StaticFS("/admin/static", http.FS(staticembed.FS))

	for path, want := range map[string]string{
		"/admin/static/logo.png":    "operator-logo",
		"/admin/static/favicon.png": "operator-favicon",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, want, w.Body.String())
		})
	}
}

// Without any branding configured the embedded assets are still served, so an
// unconfigured deployment keeps its logo rather than losing it to an aborted
// request.
func TestAdminStaticAssetsFallBackToTheEmbeddedLogo(t *testing.T) {
	s := setupTestService(t)

	embedded, err := staticembed.FS.ReadFile("logo.png")
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(s.httpHelpers.Middleware.CustomBranding(model.Branding{}))
	engine.StaticFS("/admin/static", http.FS(staticembed.FS))

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/static/logo.png", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, embedded, w.Body.Bytes())
}
