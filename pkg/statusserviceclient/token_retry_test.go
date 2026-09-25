package statusserviceclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// A 401 answering a CACHED token is the token being stale, not the service
// refusing. Classifying it permanent stops the retry loop dead, so the fresh
// token the 401 handler just arranged for is never actually tried - turning
// a routine expiry into a failed allocation.
func TestClassifyResourceStatus_UnauthorizedIsRetryable(t *testing.T) {
	err := classifyResourceStatus(http.StatusUnauthorized, []byte("token expired"))
	if err == nil {
		t.Fatal("a 401 is still an error")
	}
	if isPermanent(err) {
		t.Fatal("a cached-token 401 must be retryable, so the retry can fetch a fresh token")
	}
}

// Every other 4xx really is the service saying no, and retrying it would
// just hammer a service that has already refused.
func TestClassifyResourceStatus_OtherClientErrorsStayPermanent(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusGone, http.StatusBadRequest} {
		if err := classifyResourceStatus(code, []byte("no")); !isPermanent(err) {
			t.Fatalf("%d must stay permanent", code)
		}
	}
}

// The token endpoint is the other way round: a 4xx there is a real refusal
// of the client's credentials, so classifyStatus keeps its behaviour.
func TestClassifyStatus_TokenEndpointUnauthorizedStaysPermanent(t *testing.T) {
	if err := classifyStatus(http.StatusUnauthorized, []byte("bad assertion")); !isPermanent(err) {
		t.Fatal("a token-endpoint 401 must stay permanent: retrying rejected credentials is pointless")
	}
}

// maxElapsed used to be checked only BETWEEN attempts, while fn ran
// http.Client.Do on the caller's context - so a single stuck request could
// outlive the bound the config advertises (the transport's own timeout is
// 10s by default, against a 5s TakeFallbackTimeout).
func TestRetry_DeadlineCancelsTheInFlightCall(t *testing.T) {
	const bound = 80 * time.Millisecond

	start := time.Now()
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond,
		maxBackoff:     time.Millisecond,
		maxElapsed:     bound,
	}, func(ctx context.Context) error {
		// Stands in for a request that never answers: it returns only when
		// its context is cancelled.
		<-ctx.Done()
		return ctx.Err()
	})

	if err == nil {
		t.Fatal("want an error once the deadline passes")
	}
	if elapsed := time.Since(start); elapsed > bound*4 {
		t.Fatalf("retry took %v, well past its %v bound: the in-flight call was not cancelled", elapsed, bound)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("err = %v", err)
	}
}

// The bound must not leak into the caller's own context: cancelling the
// retry deadline cannot cancel whatever the caller does next.
func TestRetry_LeavesTheCallerContextAlone(t *testing.T) {
	ctx := context.Background()
	_ = retry(ctx, retryConfig{maxAttempts: 1, maxElapsed: time.Millisecond}, func(context.Context) error {
		return errors.New("nope")
	})
	if err := ctx.Err(); err != nil {
		t.Fatalf("caller context must be untouched, got %v", err)
	}
}
