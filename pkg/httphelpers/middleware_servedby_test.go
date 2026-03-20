package httphelpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServedBy_ConfiguredValue(t *testing.T) {
	m := newTestMiddleware(t)
	ctx := context.Background()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(m.ServedBy(ctx, "custom-node-42"))
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "custom-node-42", w.Header().Get("X-Served-By"))
}

func TestServedBy_EmptyConfigNoHeader(t *testing.T) {
	m := newTestMiddleware(t)
	ctx := context.Background()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(m.ServedBy(ctx, ""))
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("X-Served-By"))
}

func TestServedBy_HostnameSentinel(t *testing.T) {
	m := newTestMiddleware(t)
	ctx := context.Background()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(m.ServedBy(ctx, "hostname"))
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	expected, err := os.Hostname()
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expected, w.Header().Get("X-Served-By"))
}

func TestServedBy_HeaderSetOnEveryResponse(t *testing.T) {
	m := newTestMiddleware(t)
	ctx := context.Background()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(m.ServedBy(ctx, "node-a"))
	r.GET("/a", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/b", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, path := range []string{"/a", "/b"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, "node-a", w.Header().Get("X-Served-By"), "path: %s", path)
	}
}

func TestServedBy_HostnameSentinelDoesNotPanic(t *testing.T) {
	m := newTestMiddleware(t)
	ctx := context.Background()

	gin.SetMode(gin.TestMode)

	assert.NotPanics(t, func() {
		r := gin.New()
		r.Use(m.ServedBy(ctx, "hostname"))
		r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		r.ServeHTTP(w, req)

		assert.NotEmpty(t, w.Header().Get("X-Served-By"))
	})
}
