package httphelpers

import (
	"context"
	"fmt"
	"os"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/lithammer/shortuuid/v4"
	ginratelimit "github.com/ljahier/gin-ratelimit"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

type middlewareHandler struct {
	client *Client
	log    *logger.Log
}

// Duration middleware to calculate the duration of the request and set it in the gin context
func (m *middlewareHandler) Duration(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Duration")
	defer span.End()

	return func(c *gin.Context) {
		t := time.Now()
		c.Next()
		duration := time.Since(t)
		c.Set("duration", duration)
	}
}

// RequestID middleware to set a unique request ID in the gin context and header
func (m *middlewareHandler) RequestID(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:RequestID")
	defer span.End()

	return func(c *gin.Context) {
		id := shortuuid.New()
		c.Set("req_id", id)
		c.Header("req_id", id)
		c.Next()
	}
}

// Logger middleware to log the request details.
// Successful (HTTP 200) requests to "/health" are always excluded from the
// access log to reduce noise from monitoring probes.
func (m *middlewareHandler) Logger(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Logger")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		c.Next()

		status := c.Writer.Status()
		if c.Request.URL.Path == "/health" && status == 200 {
			return
		}

		log.Info("request", "status", status, "url", c.Request.URL.String(), "method", c.Request.Method, "req_id", c.GetString("req_id"))
	}
}

// AuthLog middleware to log the request details with the user information
func (m *middlewareHandler) AuthLog(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:AuthLog")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		u, _ := c.Get("user")
		c.Next()
		log.Info("auth", "user", u, "req_id", c.GetString("req_id"))
	}
}

// Crash middleware to recover from panics and return a 500 error
func (m *middlewareHandler) Crash(ctx context.Context) gin.HandlerFunc {
	ctx, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Crash")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				status := c.Writer.Status()
				log.Error(nil, "panic recovered", "error", r, "status", status, "url", c.Request.URL.Path, "method", c.Request.Method)
				m.client.Rendering.Content(ctx, c, 500, gin.H{"data": nil, "error": helpers.NewErrorDetails("internal_server_error", r)})
			}
		}()
		c.Next()
	}
}

// ClientCertAuth middleware to authenticate the client certificate, this should compare client certificate SAH1 hash with some config value.
func (m *middlewareHandler) ClientCertAuth(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:ClientCertAuth")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		clientCertSHA1 := c.Request.Header.Get("X-SSL-Client-SHA1")
		log.Info("clientCertSHA1", "clientCertSHA1", clientCertSHA1)
		fmt.Println("clientCertSHA1", clientCertSHA1)
		c.Next()
	}
}

// BasicAuth middleware to authenticate the user with basic auth
func (m *middlewareHandler) BasicAuth(ctx context.Context, users map[string]string) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:BasicAuth")
	defer span.End()

	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", `Basic realm="restricted"`)
			c.AbortWithStatus(401)
			return
		}

		password, found := users[user]
		if !found || pass != password {
			c.Header("WWW-Authenticate", `Basic realm="restricted"`)
			c.AbortWithStatus(401)
			return
		}

		c.Set("user", user)
		c.Next()
		m.log.Info("basic_auth", "user", user, "req_id", c.GetString("req_id"))
	}
}

// Gzip middleware sets the compression level
func (m *middlewareHandler) Gzip(ctx context.Context) gin.HandlerFunc {
	return gzip.Gzip(gzip.DefaultCompression)
}

func (m *middlewareHandler) UserSession(name, authKey, encKey string, opts sessions.Options) gin.HandlerFunc {
	store := cookie.NewStore([]byte(authKey), []byte(encKey))
	store.Options(opts)
	return sessions.Sessions(name, store)
}

// RateLimiter implements a token bucket rate limiter using gin-ratelimit
type RateLimiter struct {
	tokenBucket *ginratelimit.TokenBucket
}

// NewRateLimiter creates a new rate limiter using token bucket algorithm.
// requestsPerMinute: maximum requests allowed per minute per IP
func (m *middlewareHandler) NewRateLimiter(requestsPerMinute int) *RateLimiter {
	tb := ginratelimit.NewTokenBucket(requestsPerMinute, 1*time.Minute)
	return &RateLimiter{
		tokenBucket: tb,
	}
}

// Middleware returns a Gin middleware handler that enforces rate limiting by IP
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return ginratelimit.RateLimitByIP(rl.tokenBucket)
}

// CustomBranding returns a middleware that serves custom logo and favicon files
// when configured in common.branding. Requests not matching /static/logo.png or
// /static/favicon.png are passed through unchanged.
func (m *middlewareHandler) CustomBranding(branding model.Branding) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.URL.Path {
		case "/static/logo.png":
			if branding.LogoPath != "" {
				if _, err := os.Stat(branding.LogoPath); err == nil {
					c.File(branding.LogoPath)
					c.Abort()
					return
				}
			}
		case "/static/favicon.png":
			if branding.FaviconPath != "" {
				if _, err := os.Stat(branding.FaviconPath); err == nil {
					c.File(branding.FaviconPath)
					c.Abort()
					return
				}
			}
		}
		c.Next()
	}
}
