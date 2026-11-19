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

// A cancelled caller is told it cancelled, not that the service failed.
//
// The loop used to return the last attempt's error, so errors.Is(err,
// context.Canceled) answered false and an issuer deciding what to do about
// an unreachable status service could not tell "the service is down" from
// "I cancelled my own request". Both facts are kept now.
func TestRetryReportsCancellationAsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	serviceErr := errors.New("status service returned 503: down")
	attempts := 0
	err := retry(ctx, retryConfig{initialBackoff: time.Hour, maxBackoff: time.Hour}, func(context.Context) error {
		attempts++
		cancel() // the caller gives up while a retry is pending
		return serviceErr
	})

	if err == nil {
		t.Fatal("a cancelled retry must fail")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller cancelled; errors.Is(err, context.Canceled) must answer: %v", err)
	}
	if !errors.Is(err, serviceErr) {
		t.Fatalf("the last attempt's failure is the diagnosis and must survive: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("a cancelled context must stop the loop, ran %d attempts", attempts)
	}
}

// Giving up after maxElapsed is a deadline, and says so.
func TestRetryReportsItsOwnDeadlineAsADeadline(t *testing.T) {
	serviceErr := errors.New("status service returned 503: down")
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond, maxBackoff: time.Millisecond,
		maxElapsed: 20 * time.Millisecond,
	}, func(context.Context) error { return serviceErr })

	// Independently, not as one arm of an OR: serviceErr is always wrapped,
	// so an OR with it passes whether or not the deadline survived, and the
	// give-up path could drop context.DeadlineExceeded undetected.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("giving up after maxElapsed is a deadline and must say so: %v", err)
	}
	if !errors.Is(err, serviceErr) {
		t.Fatalf("the service failure must survive the give-up: %v", err)
	}
}

// And an uncancelled failure is still just the failure: no context error
// invented where none happened.
func TestRetryDoesNotInventACancellation(t *testing.T) {
	serviceErr := errors.New("status service returned 503: down")
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond, maxBackoff: time.Millisecond, maxAttempts: 2,
	}, func(context.Context) error { return serviceErr })

	if !errors.Is(err, serviceErr) {
		t.Fatalf("want the service error, got %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("nothing was cancelled: %v", err)
	}
}

// The give-up after maxElapsed says so from EVERY path that reaches it.
//
// There are three ways this loop can stop on a context: the check at the
// top, the select during backoff, and the elapsed check between attempts.
// The first two were fixed together and this one was missed, which an
// assertion written as "deadline OR service error" could never have caught
// - serviceErr is always wrapped, so the OR was satisfied either way.
//
// fn outruns maxElapsed here, so the elapsed check fires immediately after
// it returns, before any select on ctx.Done().
func TestRetryReportsTheDeadlineFromTheElapsedPathToo(t *testing.T) {
	serviceErr := errors.New("status service returned 503: down")

	start := time.Now()
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Hour, maxBackoff: time.Hour,
		maxElapsed: 20 * time.Millisecond,
	}, func(context.Context) error {
		time.Sleep(50 * time.Millisecond)
		return serviceErr
	})

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the loop slept the backoff instead of giving up: %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("giving up on the elapsed check is still a deadline: %v", err)
	}
	if !errors.Is(err, serviceErr) {
		t.Fatalf("the service failure must survive it: %v", err)
	}
}
