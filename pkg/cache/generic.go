package cache

import (
	"context"
	"time"
)

// Logger is a minimal logging interface for operational error reporting.
// Both *logger.Log and logr.Logger satisfy this interface.
type Logger interface {
	Error(err error, msg string, keysAndValues ...any)
}

// nopLogger silently discards all log output.
type nopLogger struct{}

func (nopLogger) Error(_ error, _ string, _ ...any) {}

// Cache is a generic key-value cache interface with TTL support.
// All in-memory caches MUST use this interface to allow swapping backends
// for HA deployments (e.g. memory → mongo).
//
// V is the value type. Keys are always strings, which covers all
// current usage across the codebase.
type Cache[V any] interface {
	// Get retrieves a value by key. Returns the value and true if found,
	// or the zero value and false if not found or expired.
	Get(ctx context.Context, key string) (V, bool)

	// Set stores a value with the default TTL configured at creation time.
	Set(ctx context.Context, key string, value V)

	// SetWithTTL stores a value with a custom TTL, overriding the default.
	SetWithTTL(ctx context.Context, key string, value V, ttl time.Duration)

	// Delete removes a value by key.
	Delete(ctx context.Context, key string)

	// Len returns the number of items currently in the cache.
	Len() int
}
