package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// fastConfig returns a Config with retry/refill timing shrunk to keep tests
// fast, pointed at fake's endpoints.
func fastConfig(fake *fakeStatusService, key *ecdsa.PrivateKey) Config {
	return fastConfigAs(fake, "https://issuer.example.org", key)
}

func fastConfigAs(fake *fakeStatusService, issuerID string, key *ecdsa.PrivateKey) Config {
	return Config{
		IngestionURL:        fake.ingestionURL,
		ASURL:               fake.asURL,
		IssuerID:            issuerID,
		Key:                 key,
		PoolSize:            5,
		LowWaterMark:        2,
		RetryInitialBackoff: 5 * time.Millisecond,
		RetryMaxBackoff:     20 * time.Millisecond,
		TakeFallbackTimeout: 2 * time.Second,
		RefillInterval:      50 * time.Millisecond,
	}
}

// TestClientAllocateAndSetStatus_EndToEnd exercises the full path against a
// real HTTP server (fakeStatusService) performing genuine client-assertion
// verification: token fetch, pool refill, Take, and SetStatus (both a
// success and an ownership rejection).
func TestClientAllocateAndSetStatus_EndToEnd(t *testing.T) {
	fake := newFakeStatusService(t)
	key := testKey(t)

	c, err := New(fastConfig(fake, key), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// The background loop should fill the pool to PoolSize without any
	// Take call forcing it.
	deadline := time.Now().Add(2 * time.Second)
	for c.PoolLen() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.PoolLen(); got != 5 {
		t.Fatalf("pool did not fill in the background: got %d, want 5", got)
	}

	entry, err := c.Take(context.Background())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if entry.ListID != "list-a" {
		t.Fatalf("ListID = %q, want list-a", entry.ListID)
	}
	if entry.ListURL == "" {
		t.Fatal("ListURL is empty")
	}

	if err := c.SetStatus(context.Background(), entry.ListID, entry.Index, StatusInvalid); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	fake.mu.Lock()
	calls := fake.statusCalls
	fake.mu.Unlock()
	if len(calls) != 1 || calls[0].status != "INVALID" {
		t.Fatalf("status calls = %+v, want exactly one INVALID", calls)
	}

	// Only the exact tokenCalls this test needed so far - proves the token
	// is cached rather than re-fetched on every allocate/status call.
	// Checked here, before a second client (below) starts fetching its own
	// tokens against the same fake and would otherwise be counted too.
	if calls := fake.tokenCalls.Load(); calls > 2 {
		t.Fatalf("token fetched %d times; expected caching to keep this small", calls)
	}

	// A different issuer identity must not be able to revoke this index -
	// exercised to confirm the fake actually enforces ownership like the
	// real service does, so the success case above is meaningful.
	otherKey := testKey(t)
	other, err := New(fastConfigAs(fake, "https://someone-else.example.org", otherKey), nil)
	if err != nil {
		t.Fatalf("New (other issuer): %v", err)
	}
	defer other.Close()

	err = other.SetStatus(context.Background(), entry.ListID, entry.Index, StatusSuspended)
	if err == nil {
		t.Fatal("a different issuer identity must not be able to update this index")
	}
	if !isPermanent(err) {
		t.Fatalf("an ownership rejection must be permanent (not retried), got %v", err)
	}
}

// TestPoolRefillsBelowLowWaterMark drains the pool via Take and checks the
// background loop brings it back up once it crosses LowWaterMark.
func TestPoolRefillsBelowLowWaterMark(t *testing.T) {
	fake := newFakeStatusService(t)
	c, err := New(fastConfig(fake, testKey(t)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for c.PoolLen() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Drain to right at the low-water mark boundary.
	for range 4 {
		if _, err := c.Take(context.Background()); err != nil {
			t.Fatalf("Take: %v", err)
		}
	}
	if got := c.PoolLen(); got != 1 {
		t.Fatalf("pool len after draining 4 = %d, want 1", got)
	}

	deadline = time.Now().Add(2 * time.Second)
	for c.PoolLen() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.PoolLen(); got != 5 {
		t.Fatalf("pool did not refill after crossing the low-water mark: got %d, want 5", got)
	}
}

// TestTakeFallbackRetriesTransientFailures makes /allocate fail twice with
// 500s (a real, in-flight HTTP round trip each time - not a mocked
// function call) before succeeding, and checks Take's synchronous fallback
// retries through that and still returns an entry, well within
// TakeFallbackTimeout.
func TestTakeFallbackRetriesTransientFailures(t *testing.T) {
	fake := newFakeStatusService(t)
	fake.allocateFailures.Store(2)
	fake.allocateFailureStatus = http.StatusServiceUnavailable

	cfg := fastConfig(fake, testKey(t))
	cfg.PoolSize = 1 // never satisfied by the background loop alone in time; forces Take's fallback path once drained
	c, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// Drain whatever the background loop may have already put in, so the
	// next Take is guaranteed to hit the fallback path.
	for c.PoolLen() > 0 {
		if _, err := c.Take(context.Background()); err != nil {
			t.Fatalf("draining Take: %v", err)
		}
	}

	start := time.Now()
	entry, err := c.Take(context.Background())
	if err != nil {
		t.Fatalf("Take should have recovered after transient failures: %v", err)
	}
	if elapsed := time.Since(start); elapsed > cfg.TakeFallbackTimeout {
		t.Fatalf("Take took %v, longer than its own fallback timeout %v", elapsed, cfg.TakeFallbackTimeout)
	}
	if entry.ListURL == "" {
		t.Fatal("got an empty entry back")
	}
}

// TestTakeFailsFastOnPermanentFailure checks that a 400 from /allocate is
// not retried - Take should fail quickly, not burn its whole
// TakeFallbackTimeout budget.
func TestTakeFailsFastOnPermanentFailure(t *testing.T) {
	fake := newFakeStatusService(t)
	fake.allocateFailures.Store(1 << 30) // effectively "always fails"
	fake.allocateFailureStatus = http.StatusBadRequest

	cfg := fastConfig(fake, testKey(t))
	cfg.TakeFallbackTimeout = 2 * time.Second
	c, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	start := time.Now()
	_, err = c.Take(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want an error when the status service permanently rejects allocation")
	}
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want an error wrapping ErrPoolExhausted, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("a permanent (400) failure should fail fast, not retry for %v", elapsed)
	}
}

// TestSetStatusRetriesTransientFailures mirrors the allocate case for
// PATCH /status.
func TestSetStatusRetriesTransientFailures(t *testing.T) {
	fake := newFakeStatusService(t)
	c, err := New(fastConfig(fake, testKey(t)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for c.PoolLen() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	entry, err := c.Take(context.Background())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	fake.statusFailures.Store(2)
	fake.statusFailureStatus = http.StatusInternalServerError

	if err := c.SetStatus(context.Background(), entry.ListID, entry.Index, StatusInvalid); err != nil {
		t.Fatalf("SetStatus should have recovered after transient failures: %v", err)
	}
	if got := fake.statusCallCount.Load(); got != 3 { // 2 failures + 1 success
		t.Fatalf("status endpoint hit %d times, want 3 (2 failures + success)", got)
	}
}

// TestSetStatusDoesNotRetryPermanentFailure checks a 403 (not owner) is
// returned immediately, without retrying.
func TestSetStatusDoesNotRetryPermanentFailure(t *testing.T) {
	fake := newFakeStatusService(t)
	c, err := New(fastConfig(fake, testKey(t)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for c.PoolLen() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	entry, err := c.Take(context.Background())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	// Simulate a permanent rejection by asking to update an index nobody
	// owns (a synthetic, never-allocated index under this list).
	err = c.SetStatus(context.Background(), entry.ListID, entry.Index+1000, StatusInvalid)
	if err == nil {
		t.Fatal("want an error for an unknown index")
	}
	if got := fake.statusCallCount.Load(); got != 1 {
		t.Fatalf("a permanent (404) failure must not be retried; status endpoint hit %d times", got)
	}
}

// TestListIDFromURL checks the list-URL-to-list-ID extraction used to turn
// an /allocate response's list_url into what PATCH /status needs.
func TestListIDFromURL(t *testing.T) {
	got, err := ListIDFromURL("https://status.example.org/lists/abc123")
	if err != nil {
		t.Fatalf("ListIDFromURL: %v", err)
	}
	if got != "abc123" {
		t.Fatalf("got %q, want abc123", got)
	}

	// A control character makes url.Parse itself fail; the point of the
	// case is that a malformed input is rejected rather than silently
	// yielding some substring as a list ID.
	if _, err := ListIDFromURL("not a url with a path\x7f"); err == nil {
		t.Fatal("want an error for a URL containing a control character")
	}
	if _, err := ListIDFromURL("https://status.example.org/"); err == nil {
		t.Fatal("want an error for a URL with no list ID segment")
	}
}
