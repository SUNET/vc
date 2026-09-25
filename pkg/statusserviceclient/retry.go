package statusserviceclient

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// retryConfig bounds an exponential-backoff-with-full-jitter retry loop.
//
// Zero maxAttempts and zero maxElapsed both mean "unbounded" - retry() then
// only stops on success, a permanent error, or ctx cancellation. This is
// used for the pool's background refill loop (see Client.backgroundRetry),
// which has nothing better to do than keep trying while a caller elsewhere
// (Take's fallback, bounded by TakeFallbackTimeout) may be giving up much
// sooner on the exact same kind of failure.
type retryConfig struct {
	initialBackoff time.Duration
	maxBackoff     time.Duration
	maxElapsed     time.Duration
	maxAttempts    int
}

// permanentError marks an error retrying cannot fix - a 4xx response from
// the status service (bad request, unauthorized, forbidden, not found,
// gone). retry gives up immediately on one of these instead of spending its
// backoff budget on something that will never succeed.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// permanent wraps err so retry() treats it as non-retryable. A nil err
// passes through unchanged.
func permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// isPermanent reports whether err (or something it wraps) was marked
// permanent by permanent().
func isPermanent(err error) bool {
	var pe *permanentError
	return errors.As(err, &pe)
}

// retry calls fn until it succeeds, returns a permanent error, exhausts
// cfg's bounds, or ctx is cancelled. Backoff is full-jitter (uniform random
// in [0, current backoff)) to avoid multiple replicas of the same issuer
// retrying against a recovering status service in lockstep.
func retry(ctx context.Context, cfg retryConfig, fn func(ctx context.Context) error) error {
	backoff := cfg.initialBackoff
	if backoff <= 0 {
		backoff = defaultRetryInitialBackoff
	}
	maxBackoff := cfg.maxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultRetryMaxBackoff
	}

	// Bound the whole operation, fn's own HTTP call included. Checking
	// maxElapsed only between attempts bounds the RETRY loop but not the
	// request inside it: http.Client.Do gets this same ctx, and its own
	// timeout is the transport's (10s by default) not ours, so one stuck
	// request could outlive a 5s TakeFallbackTimeout and block a caller
	// past the bound the config advertises.
	if cfg.maxElapsed > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.maxElapsed)
		defer cancel()
	}

	start := time.Now()
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		err := fn(ctx)
		if err == nil {
			return nil
		}
		if isPermanent(err) {
			return err
		}
		lastErr = err

		if cfg.maxAttempts > 0 && attempt >= cfg.maxAttempts {
			return lastErr
		}
		if cfg.maxElapsed > 0 && time.Since(start) >= cfg.maxElapsed {
			return lastErr
		}

		sleep := time.Duration(0)
		if backoff > 0 {
			sleep = time.Duration(rand.Int63n(int64(backoff))) //nolint:gosec // jitter timing, not a cryptographic use
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(sleep):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
