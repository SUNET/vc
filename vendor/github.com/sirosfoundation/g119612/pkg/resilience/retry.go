// Package resilience provides retry and error classification utilities for HTTP
// fetch operations used by trust list and entity list fetchers.
package resilience

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Config configures retry behavior for HTTP fetch operations.
type Config struct {
	// MaxAttempts is the maximum number of fetch attempts (1 = no retry).
	// Default: 3 (1 initial + 2 retries).
	MaxAttempts int

	// RetryBaseDelay is the initial backoff duration; doubled after each attempt.
	// Default: 500ms.
	RetryBaseDelay time.Duration

	// MaxBodyBytes limits the response body size. An error is returned if the
	// response exceeds this limit. Default: 10MB.
	MaxBodyBytes int64
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		MaxAttempts:    3,
		RetryBaseDelay: 500 * time.Millisecond,
		MaxBodyBytes:   10 << 20, // 10 MB
	}
}

// WithDefaults returns a copy of the config with zero fields set to defaults.
func (c Config) WithDefaults() Config {
	out := c
	if out.MaxAttempts <= 0 {
		out.MaxAttempts = 3
	}
	if out.RetryBaseDelay <= 0 {
		out.RetryBaseDelay = 500 * time.Millisecond
	}
	if out.MaxBodyBytes <= 0 {
		out.MaxBodyBytes = 10 << 20
	}
	return out
}

// TransportError wraps a network/transport-level error (DNS, TCP, TLS).
type TransportError struct {
	Err error
}

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

// HTTPStatusError represents a non-200 HTTP response.
type HTTPStatusError struct {
	StatusCode int
	URL        string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d from %s", e.StatusCode, e.URL)
}

// IsRetryable reports whether err is a transient error worth retrying:
// transport errors and 5xx HTTP responses.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if te, ok := err.(*TransportError); ok {
		_ = te
		return true
	}
	if se, ok := err.(*HTTPStatusError); ok {
		return se.StatusCode >= http.StatusInternalServerError
	}
	return false
}

// DoWithRetry executes fn with retry and exponential backoff.
//
// fn is called up to config.MaxAttempts times. If fn returns an error that
// IsRetryable classifies as transient (transport errors, 5xx), it is retried
// after exponential backoff. Non-retryable errors (4xx, parse errors) fail
// immediately.
//
// The context is checked between retries; if cancelled, the context error is
// returned immediately.
func DoWithRetry(ctx context.Context, cfg Config, fn func() error) error {
	cfg = cfg.WithDefaults()
	var lastErr error
	backoff := cfg.RetryBaseDelay

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err

		if !IsRetryable(err) {
			return err
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}
