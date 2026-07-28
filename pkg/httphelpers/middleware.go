package httphelpers

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

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

// ServedBy middleware sets the X-Served-By response header for HA troubleshooting.
// The header is opt-in to avoid leaking internal hostnames on internet-facing endpoints.
//   - empty string: header is not set (default)
//   - "hostname": resolved to os.Hostname() once at startup
//   - any other value: used as-is
func (m *middlewareHandler) ServedBy(ctx context.Context, servedByHeader string) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:ServedBy")
	defer span.End()

	if servedByHeader == "" {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	value := servedByHeader
	if value == "hostname" {
		hostname, err := os.Hostname()
		if err != nil {
			m.log.Error(err, "failed to get hostname for X-Served-By header")
			hostname = "unknown"
		}
		value = hostname
	}

	return func(c *gin.Context) {
		c.Header("X-Served-By", value)
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
				m.client.Rendering.Content(ctx, c, 500, gin.H{"data": nil, "error": helpers.NewErrorDetails("internal_server_error", "an unexpected error occurred")})
			}
		}()
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
		if !found || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
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

// SessionOrAPIAuth returns middleware that accepts either a valid session (identified by sessionKey)
// or falls through to the provided API auth middleware. When a session is present and a SPOCP
// engine is provided, the middleware runs the same method+path+subject authorization check that
// API clients go through, so one set of rules governs both paths.
func (m *middlewareHandler) SessionOrAPIAuth(sessionKey string, apiAuth gin.HandlerFunc, engine *SafeEngine, service string) gin.HandlerFunc {
	log := m.log.New("session_or_api_auth")
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if auth := session.Get(sessionKey); auth != true {
			// No session — fall through to JWT + SPOCP middleware.
			apiAuth(c)
			return
		}

		subject, _ := session.Get("admin_subject").(string)

		// SPOCP authorization check.
		if engine != nil {
			if subject == "" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session missing subject"})
				return
			}

			// Store allowedAuthenticSources authentic sources and scopes for downstream handlers (DB filtering).
			allowedAuthenticSources := AllowedAuthenticSources(engine, subject)
			c.Set("spocp_allowed_authentic_sources", allowedAuthenticSources)
			allowedScopes := AllowedScopes(engine, subject)
			c.Set("spocp_allowed_scopes", allowedScopes)

			// For session users, resource-level SPOCP checks only apply when
			// the request carries explicit resource pairs. Search/list endpoints
			// without resource params rely on DB-level filtering via the allowed
			// lists above.
			pairs := extractResourcePairs(c)
			for _, p := range pairs {
				query := BuildSPOCPQuery(service, c.Request.Method, c.FullPath(), subject, p.authenticSource, p.scope)
				if !engine.QueryElement(query) {
					log.Info("spocp_denied", "subject", subject, "service", service, "method", c.Request.Method, "path", c.FullPath(),
						"authentic_source", p.authenticSource, "scope", p.scope)
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
					return
				}
			}
		}

		c.Next()
	}
}

// resourcePair holds an authentic_source+scope combination extracted from the request.
type resourcePair struct {
	authenticSource string
	scope           string
}

// extractResourcePairs collects all (authentic_source, scope) pairs from
// query parameters and the JSON body so that each pair can be checked against
// the SPOCP engine independently.
func extractResourcePairs(c *gin.Context) []resourcePair {
	var pairs []resourcePair

	// Query/form parameters (GET endpoints).
	qSource := c.Query("authentic_source")
	qScope := c.Query("scope")
	if qSource != "" || qScope != "" {
		pairs = append(pairs, resourcePair{authenticSource: qSource, scope: qScope})
	}

	// JSON body (POST/PUT/DELETE endpoints).
	if c.Request.Body != nil && c.Request.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err == nil {
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			pairs = append(pairs, extractBodyResourcePairs(bodyBytes)...)
		}
	}

	// Inject synthetic scope for identity mapping endpoints — these have
	// authentic_source but no scope in the document model.
	if strings.Contains(c.FullPath(), "/identity/mapping") {
		for i := range pairs {
			if pairs[i].authenticSource != "" && pairs[i].scope == "" {
				pairs[i].scope = "identity_mapping"
			}
		}
	}

	return deduplicatePairs(pairs)
}

// extractBodyResourcePairs parses a JSON body and returns all
// (authentic_source, scope) pairs found at known paths:
//
//   - $.authentic_source / $.scope
//   - $.meta.authentic_source / $.meta.scope
//   - $.documents.*.meta.authentic_source / $.documents.*.meta.scope
//   - $.mappings.*.authentic_source
func extractBodyResourcePairs(body []byte) []resourcePair {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var pairs []resourcePair

	// Top-level.
	src := jsonStringField(raw, "authentic_source")
	scope := jsonStringField(raw, "scope")
	if src != "" || scope != "" {
		pairs = append(pairs, resourcePair{authenticSource: src, scope: scope})
	}

	// $.meta
	if metaRaw, ok := raw["meta"]; ok {
		var meta map[string]json.RawMessage
		if json.Unmarshal(metaRaw, &meta) == nil {
			src := jsonStringField(meta, "authentic_source")
			scope := jsonStringField(meta, "scope")
			if src != "" || scope != "" {
				pairs = append(pairs, resourcePair{authenticSource: src, scope: scope})
			}
		}
	}

	// $.documents.*.meta (BulkUpload)
	if docsRaw, ok := raw["documents"]; ok {
		var docs map[string]json.RawMessage
		if json.Unmarshal(docsRaw, &docs) == nil {
			for _, itemRaw := range docs {
				var item map[string]json.RawMessage
				if json.Unmarshal(itemRaw, &item) != nil {
					continue
				}
				if metaRaw, ok := item["meta"]; ok {
					var meta map[string]json.RawMessage
					if json.Unmarshal(metaRaw, &meta) == nil {
						src := jsonStringField(meta, "authentic_source")
						scope := jsonStringField(meta, "scope")
						if src != "" || scope != "" {
							pairs = append(pairs, resourcePair{authenticSource: src, scope: scope})
						}
					}
				}
			}
		}
	}

	// $.mappings.*.authentic_source (BulkCreate identity mappings)
	if mappingsRaw, ok := raw["mappings"]; ok {
		var mappings map[string]json.RawMessage
		if json.Unmarshal(mappingsRaw, &mappings) == nil {
			for _, itemRaw := range mappings {
				var item map[string]json.RawMessage
				if json.Unmarshal(itemRaw, &item) != nil {
					continue
				}
				src := jsonStringField(item, "authentic_source")
				if src != "" {
					pairs = append(pairs, resourcePair{authenticSource: src})
				}
			}
		}
	}

	return pairs
}

// jsonStringField unmarshals raw[key] as a string, returning "" on absence or error.
func jsonStringField(raw map[string]json.RawMessage, key string) string {
	v, ok := raw[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}

// deduplicatePairs returns unique resourcePair values preserving order.
func deduplicatePairs(pairs []resourcePair) []resourcePair {
	if len(pairs) <= 1 {
		return pairs
	}
	seen := map[resourcePair]struct{}{}
	out := make([]resourcePair, 0, len(pairs))
	for _, p := range pairs {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
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

// CSRFProtection returns middleware that enforces CSRF token validation on
// state-changing requests (POST, PUT, DELETE, PATCH) for session-authenticated users.
// The token is generated on login, stored in the session as "csrf_token", and must
// be sent by the client in the X-CSRF-Token header.
func (m *middlewareHandler) CSRFProtection(sessionKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only enforce on state-changing methods.
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Only enforce for session-authenticated users (not JWT API clients).
		session := sessions.Default(c)
		if auth := session.Get(sessionKey); auth != true {
			c.Next()
			return
		}

		token, _ := session.Get("csrf_token").(string)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing CSRF token in session"})
			return
		}

		header := c.GetHeader("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(header)) != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
			return
		}

		c.Next()
	}
}

// CustomBranding returns a middleware that serves custom logo and favicon files
// when configured in common.branding. Requests not matching /static/logo.png or
// /static/favicon.png are passed through unchanged.
func (m *middlewareHandler) CustomBranding(branding model.Branding) gin.HandlerFunc {
	log := m.log.New("branding")
	var logoOnce, faviconOnce sync.Once

	serveIfReadable := func(c *gin.Context, path string, logOnce *sync.Once) bool {
		if path == "" {
			return false
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			logOnce.Do(func() {
				if err != nil {
					log.Error(err, "custom branding file not readable, falling back to default", "path", path)
				} else {
					log.Error(nil, "custom branding path is a directory, falling back to default", "path", path)
				}
			})
			return false
		}
		f, err := os.Open(path)
		if err != nil {
			logOnce.Do(func() {
				log.Error(err, "custom branding file not readable, falling back to default", "path", path)
			})
			return false
		}
		if err := f.Close(); err != nil {
			log.Error(err, "failed to close file", "path", path)
		}
		c.File(path)
		c.Abort()
		return true
	}

	return func(c *gin.Context) {
		switch c.Request.URL.Path {
		case "/static/logo.png":
			if serveIfReadable(c, branding.LogoPath, &logoOnce) {
				return
			}
		case "/static/favicon.png":
			if serveIfReadable(c, branding.FaviconPath, &faviconOnce) {
				return
			}
		}
		c.Next()
	}
}

// MaxBodySize returns middleware that limits the size of request bodies.
// Requests exceeding maxBytes receive a 413 Payload Too Large response.
func (m *middlewareHandler) MaxBodySize(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// SecurityHeaders returns middleware that sets standard security headers on all responses.
// When tlsEnabled is true, HSTS (Strict-Transport-Security) is also set.
func (m *middlewareHandler) SecurityHeaders(tlsEnabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		if tlsEnabled {
			// max-age=63072000 = 2 years; includeSubDomains applies to all subdomains
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}

// AdminCSP returns middleware that sets a restrictive Content-Security-Policy for admin UI pages.
func (m *middlewareHandler) AdminCSP() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'")
		c.Next()
	}
}
