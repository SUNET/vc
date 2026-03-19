package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter provides per-IP rate limiting for API endpoints.
// It uses the token bucket algorithm from golang.org/x/time/rate to
// limit the number of requests per second from each IP address.
type RateLimiter struct {
	limiters   map[string]*rate.Limiter
	lastAccess map[string]time.Time
	mu         sync.RWMutex
	rps        int // requests per second
	burst      int // burst size
}

// NewRateLimiter creates a new rate limiter with the specified requests per second.
// The burst parameter allows temporary exceeding of the rate limit.
//
// Parameters:
//   - rps: Maximum requests per second allowed per IP address
//   - burst: Maximum burst size (number of requests that can be made in a burst)
//
// Example:
//
//	limiter := NewRateLimiter(100, 10) // Allow 100 req/sec with bursts up to 10
func NewRateLimiter(rps, burst int) *RateLimiter {
	return &RateLimiter{
		limiters:   make(map[string]*rate.Limiter),
		lastAccess: make(map[string]time.Time),
		rps:        rps,
		burst:      burst,
	}
}

// getLimiter returns the rate limiter for a specific IP address.
// If no limiter exists for the IP, a new one is created.
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if exists {
		rl.mu.Lock()
		rl.lastAccess[ip] = time.Now()
		rl.mu.Unlock()
		return limiter
	}

	// Create new limiter for this IP
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rl.limiters[ip]; exists {
		rl.lastAccess[ip] = time.Now()
		return limiter
	}

	limiter = rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
	rl.limiters[ip] = limiter
	rl.lastAccess[ip] = time.Now()
	return limiter
}

// Middleware returns a Gin middleware function that enforces rate limiting.
// Requests that exceed the rate limit receive a 429 Too Many Requests response.
//
// Example usage:
//
//	limiter := NewRateLimiter(100, 10)
//	router.Use(limiter.Middleware())
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CleanupOldLimiters removes rate limiters for IPs that haven't made requests
// within the specified maxAge duration. This prevents the limiters map from
// growing unbounded over time.
// This function should be called periodically (e.g., every hour) by a background goroutine.
func (rl *RateLimiter) CleanupOldLimiters(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for ip, lastSeen := range rl.lastAccess {
		if lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
			delete(rl.lastAccess, ip)
		}
	}
}

// StartCleanupLoop runs CleanupOldLimiters periodically in a background goroutine.
// The goroutine stops when the provided done channel is closed.
func (rl *RateLimiter) StartCleanupLoop(interval, maxAge time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.CleanupOldLimiters(maxAge)
			case <-done:
				return
			}
		}
	}()
}
