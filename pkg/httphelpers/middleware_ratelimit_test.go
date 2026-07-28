package httphelpers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c := cache.NewMemoryCache[int64](1 * time.Minute)
	rl := NewRateLimiter(c, 5)

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/", func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// First 5 requests should succeed.
	for i := range 5 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should be allowed", i+1)
	}

	// 6th request should be rejected.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimiter_DifferentIPsAreIndependent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c := cache.NewMemoryCache[int64](1 * time.Minute)
	rl := NewRateLimiter(c, 2)

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/", func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Exhaust limit for IP A.
	for range 2 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// IP A is now blocked.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// IP B should still be allowed.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_DifferentPrefixesAreIndependent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c := cache.NewMemoryCache[int64](1 * time.Minute)
	rl1 := NewRateLimiter(c, 1)
	rl2 := NewRateLimiter(c, 1)

	r := gin.New()
	r.GET("/a", rl1.Middleware(), func(ctx *gin.Context) { ctx.Status(http.StatusOK) })
	r.GET("/b", rl2.Middleware(), func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Use up endpoint_a's limit.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// endpoint_a is now blocked.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/a", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// endpoint_b should still work for the same IP.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/b", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_WindowResets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Use a very short TTL for the test.
	c := cache.NewMemoryCache[int64](50 * time.Millisecond)
	rl := NewRateLimiter(c, 2)
	rl.window = 50 * time.Millisecond

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/", func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Exhaust limit.
	for range 2 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Blocked.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Wait for window to expire.
	time.Sleep(100 * time.Millisecond)

	// Should be allowed again.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_PathParamsAndQueryStringIgnored(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c := cache.NewMemoryCache[int64](1 * time.Minute)
	rl := NewRateLimiter(c, 2)

	r := gin.New()
	r.GET("/user/:id", rl.Middleware(), func(ctx *gin.Context) { ctx.Status(http.StatusOK) })

	// Different path param values share the same rate limit bucket.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/user/alice", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/user/bob?extra=param", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Third request (different path param + query string) should be blocked
	// because the route pattern /user/:id is the same for all.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/user/charlie?foo=bar&baz=1", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
