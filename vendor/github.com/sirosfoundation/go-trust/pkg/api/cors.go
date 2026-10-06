package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// corsMaxAge is how long a browser may cache a preflight result.
const corsMaxAge = 12 * time.Hour

// corsAllowedMethods is the full set of methods the API exposes. The PDP is a
// read/evaluate surface: evaluation is POST, discovery and metadata are GET.
const corsAllowedMethods = "GET, POST, OPTIONS"

// corsAllowedHeaders covers JSON request bodies and bearer authentication.
const corsAllowedHeaders = "Content-Type, Authorization"

// CORSMiddleware returns a gin middleware that answers cross-origin requests
// for the origins in allowedOrigins, and preflights them.
//
// An origin is echoed back only after matching the configured list — the
// Origin header is never reflected unchecked, which would make the allowlist
// decorative and let any site read PDP responses. Matching is
// case-insensitive, and supports the same wildcard form as the DID policy
// constraints: "https://*.example.com" matches "https://sub.example.com" but
// not the apex, and not "https://notexample.com".
//
// A port is part of the origin, so "https://*.example.com" does not match
// "https://sub.example.com:8443"; list such origins explicitly.
// The literal "*" allows any origin.
//
// Credentials are deliberately not enabled. The PDP authenticates with bearer
// tokens rather than cookies, so Access-Control-Allow-Credentials would add
// no capability while making a mistaken "*" far more dangerous.
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := false
	patterns := make([]string, 0, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			allowAll = true
			continue
		}
		if origin != "" {
			patterns = append(patterns, strings.ToLower(origin))
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			// Not a cross-origin request; nothing to negotiate.
			c.Next()
			return
		}

		// Vary regardless of the outcome: the response body is identical
		// either way, but the headers are not, so a shared cache must not
		// serve one origin's response to another.
		c.Header("Vary", "Origin")

		ok := originAllowed(origin, patterns)
		if !ok && !allowAll {
			// Not allowed: answer without CORS headers and let the browser
			// enforce. A preflight still ends here rather than falling
			// through to a route that does not exist.
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}

		if allowAll && !ok {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		if c.Request.Method == http.MethodOptions {
			c.Header("Access-Control-Allow-Methods", corsAllowedMethods)
			c.Header("Access-Control-Allow-Headers", corsAllowedHeaders)
			c.Header("Access-Control-Max-Age", strconv.Itoa(int(corsMaxAge.Seconds())))
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// originAllowed reports whether origin matches any configured pattern.
//
// Wildcard semantics deliberately match registry/didweb's matchesDomain:
// "*.example.com" covers a subdomain but not the apex, and the leading dot in
// the suffix is what stops "notexample.com" matching.
func originAllowed(origin string, patterns []string) bool {
	origin = strings.ToLower(origin)
	for _, pattern := range patterns {
		if pattern == origin {
			return true
		}
		scheme, host, ok := splitOrigin(pattern)
		if !ok || !strings.HasPrefix(host, "*.") {
			continue
		}
		originScheme, originHost, ok := splitOrigin(origin)
		if !ok || originScheme != scheme {
			continue
		}
		suffix := host[1:] // ".example.com"
		if strings.HasSuffix(originHost, suffix) && originHost != suffix[1:] {
			return true
		}
	}
	return false
}

// splitOrigin splits "https://host:port" into scheme and host[:port].
func splitOrigin(origin string) (scheme, host string, ok bool) {
	idx := strings.Index(origin, "://")
	if idx < 0 {
		return "", "", false
	}
	return origin[:idx], origin[idx+3:], true
}
