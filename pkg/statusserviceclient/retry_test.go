package statusserviceclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetrySucceedsAfterTransientFailures(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond,
		maxBackoff:     5 * time.Millisecond,
		maxElapsed:     time.Second,
	}, func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestRetryStopsImmediatelyOnPermanentError(t *testing.T) {
	attempts := 0
	sentinel := errors.New("bad request")
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond,
		maxBackoff:     5 * time.Millisecond,
		maxElapsed:     time.Second,
	}, func(ctx context.Context) error {
		attempts++
		return permanent(sentinel)
	})
	if attempts != 1 {
		t.Fatalf("attempts = %d, want exactly 1 for a permanent error", attempts)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the sentinel", err)
	}
}

func TestRetryRespectsMaxAttempts(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond,
		maxBackoff:     2 * time.Millisecond,
		maxAttempts:    4,
	}, func(ctx context.Context) error {
		attempts++
		return errors.New("always fails")
	})
	if err == nil {
		t.Fatal("want an error once maxAttempts is exhausted")
	}
	if attempts != 4 {
		t.Fatalf("attempts = %d, want 4", attempts)
	}
}

func TestRetryRespectsMaxElapsed(t *testing.T) {
	start := time.Now()
	err := retry(context.Background(), retryConfig{
		initialBackoff: 20 * time.Millisecond,
		maxBackoff:     20 * time.Millisecond,
		maxElapsed:     60 * time.Millisecond,
	}, func(ctx context.Context) error {
		return errors.New("always fails")
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want an error once maxElapsed is exhausted")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("retry ran for %v, well past its maxElapsed budget", elapsed)
	}
}

func TestRetryStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := retry(ctx, retryConfig{
		initialBackoff: 5 * time.Millisecond,
		maxBackoff:     5 * time.Millisecond,
		// unbounded otherwise - only ctx cancellation should stop this,
		// matching the pool's background refill loop's own retry config.
	}, func(ctx context.Context) error {
		attempts++
		return errors.New("always fails")
	})
	if err == nil {
		t.Fatal("want an error when the context is cancelled")
	}
	if attempts == 0 {
		t.Fatal("fn should have been attempted at least once before cancellation")
	}
}
