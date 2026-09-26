package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// getToken used to hold tokenMu across the whole retrying token exchange, so
// a caller arriving behind another fetch waited on a mutex - and a mutex
// wait cannot be cancelled. That made TakeFallbackTimeout unenforceable:
// the second caller's own deadline was ignored until the first one finished.
func TestGetToken_WaiterHonoursItsOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	var hits int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the first fetch open
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	defer close(release)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// First caller: occupies the fetch and blocks on the server.
	go func() { _, _ = c.getToken(context.Background()) }()
	// Give it time to claim the single-flight slot.
	time.Sleep(50 * time.Millisecond)

	// Second caller: its own deadline must win.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.getToken(ctx); err == nil {
		t.Fatal("want the waiter's deadline to be honoured")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("waiter blocked %v: it was pinned behind the other fetch", elapsed)
	}
}

// The list_url goes into a credential's status.status_list.uri as well as
// giving up the ID for PATCH, so anything a verifier could not resolve has
// to be refused. Deriving a good-looking ID from an unusable URL is the bad
// outcome: the client would PATCH the right entry while the credential
// carried a reference nobody can follow.
func TestListIDFromURL_RejectsUnusableURLs(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		// path.Base("/lists/") is "lists" - the collection, not a list.
		{"trailing slash", "https://status.example.org/lists/"},
		{"root only", "https://status.example.org/"},
		// Relative values yield an ID from something unresolvable.
		{"relative with path", "lists/abc"},
		{"bare segment", "abc"},
		{"scheme-relative", "//status.example.org/lists/abc"},
		{"path only", "/lists/abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, err := ListIDFromURL(tc.url); err == nil {
				t.Fatalf("%q must be rejected, got list ID %q", tc.url, id)
			}
		})
	}
}

// The shape the status service actually returns must still work.
func TestListIDFromURL_AcceptsAVerifierFacingURL(t *testing.T) {
	id, err := ListIDFromURL("https://status.example.org/lists/abc123")
	if err != nil {
		t.Fatalf("a well-formed list_url must be accepted: %v", err)
	}
	if id != "abc123" {
		t.Fatalf("got %q, want abc123", id)
	}
}

// A key on any other curve produces an assertion labelled ES256 that the
// status service rejects - and a rejection is retried, so the operator sees
// a slow loop of 4xx instead of the configuration error it is.
func TestNew_RejectsNonP256Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, err = New(Config{
		IngestionURL: "https://status.example.org",
		ASURL:        "https://as.example.org",
		IssuerID:     "https://issuer.example.org",
		Signer:       softwareSigner(key),
	}, nil)
	if err == nil {
		t.Fatal("a P-384 key must be rejected at construction")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("the error should name the required curve, got %v", err)
	}
}
