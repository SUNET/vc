package httphelpers

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomBranding_ServesCustomLogo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("fake-logo"), 0644))

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "fake-logo", w.Body.String())
}

func TestCustomBranding_ServesCustomFavicon(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	faviconPath := filepath.Join(dir, "favicon.png")
	require.NoError(t, os.WriteFile(faviconPath, []byte("fake-favicon"), 0644))

	branding := model.Branding{FaviconPath: faviconPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/favicon.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-favicon")
	})

	w := performRequest(r, "GET", "/static/favicon.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "fake-favicon", w.Body.String())
}

func TestCustomBranding_FallsBackWhenPathEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	branding := model.Branding{} // no paths configured
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenFileDoesNotExist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	branding := model.Branding{LogoPath: "/nonexistent/logo.png"}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenPathIsDirectory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	branding := model.Branding{LogoPath: dir}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenFileUnreadable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("secret"), 0000))

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_PassesThroughUnrelatedPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("fake-logo"), 0644))

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/other", func(c *gin.Context) {
		c.String(http.StatusOK, "other-content")
	})

	w := performRequest(r, "GET", "/other", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "other-content", w.Body.String())
}
