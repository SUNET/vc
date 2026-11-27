package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter implements a token bucket rate limiter per client IP
type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

// NewRateLimiter creates a new rate limiter with the specified requests per minute and burst size
func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     rate.Limit(float64(requestsPerMinute) / 60.0), // Convert to requests per second
		burst:    burst,
		cleanup:  5 * time.Minute,
	}

	// Start cleanup goroutine to prevent memory leaks
	go rl.cleanupVisitors()

	return rl
}

// getVisitor returns the rate limiter for a specific IP address
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

// cleanupVisitors periodically removes inactive visitors to prevent memory leaks
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		// Create a new map instead of deleting entries to avoid memory fragmentation
		rl.visitors = make(map[string]*rate.Limiter)
		rl.mu.Unlock()
	}
}

// Middleware returns a Gin middleware handler that enforces rate limiting
//
// Buckets are keyed by c.ClientIP(), which is only as trustworthy as the
// deployment's proxy configuration: gin trusts every proxy unless told
// otherwise (its default trusted CIDRs are 0.0.0.0/0 and ::/0), and nothing
// here calls SetTrustedProxies, so a directly reachable server takes the
// caller's own X-Forwarded-For and a client that rotates it gets a fresh
// bucket each time. True of every limiter on this server, not only this
// one; SUNET/vc#962 is where that is fixed.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP from request
		ip := c.ClientIP()

		// Check rate limit
		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitConfig holds configuration for different endpoint rate limits
type RateLimitConfig struct {
	TokenRequestsPerMinute     int
	TokenBurst                 int
	AuthorizeRequestsPerMinute int
	AuthorizeBurst             int
	RegisterRequestsPerMinute  int
	RegisterBurst              int
	// InteractionRequestsPerMinute caps POST /ui/interaction, which
	// authenticates no client and mints an authorization context, two
	// request objects and a QR image per call.
	InteractionRequestsPerMinute int
	InteractionBurst             int
}

// DefaultRateLimitConfig returns sensible default rate limit values
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		// Token endpoint: Most restrictive (sensitive operation)
		TokenRequestsPerMinute: 20,
		TokenBurst:             5,

		// Authorization endpoint: Moderate limits
		AuthorizeRequestsPerMinute: 60,
		AuthorizeBurst:             10,

		// Registration endpoint: Very restrictive (rarely used)
		RegisterRequestsPerMinute: 5,
		RegisterBurst:             2,

		// Standalone presentation start: as the authorization endpoint,
		// which is the same act reached through the OIDC flow. A person
		// starting, reloading and retrying a presentation stays well
		// inside it; a script minting sessions does not.
		InteractionRequestsPerMinute: 60,
		InteractionBurst:             10,
	}
}
