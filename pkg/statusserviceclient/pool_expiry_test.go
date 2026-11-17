package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
)

// newExpiryTestPool builds a pool without starting any background loop -
// take() is pure enough to test on its own, and a refill goroutine would
// race the assertions.
func newExpiryTestPool(t *testing.T, entries ...Entry) *pool {
	t.Helper()
	c := &Client{cfg: Config{PoolSize: 8, LowWaterMark: 1}, log: logger.NewSimple("test")}
	p := newPool(c)
	p.push(entries...)
	return p
}

// An entry that expires while it sits in the pool must never be handed out:
// it would go into an issued credential's status_list reference, and the
// verifier resolving it is the one who would discover the problem.
func TestPoolTake_SkipsExpiredEntries(t *testing.T) {
	fresh := Entry{ListURL: "https://s.example/l/fresh", ListID: "fresh", Index: 1, Exp: time.Now().Add(time.Hour)}
	stale := Entry{ListURL: "https://s.example/l/stale", ListID: "stale", Index: 2, Exp: time.Now().Add(-time.Minute)}

	// stale is pushed last, so it is the first take() reaches.
	p := newExpiryTestPool(t, fresh, stale)

	got, ok := p.take()
	if !ok {
		t.Fatal("want an entry: one of the two is still valid")
	}
	if got.ListID != "fresh" {
		t.Fatalf("want the unexpired entry, got %q", got.ListID)
	}
	if p.size() != 0 {
		t.Fatalf("the expired entry must be discarded, not left behind: size=%d", p.size())
	}
}

// An entry inside the skew window is as useless as an expired one: it has to
// survive being signed into a credential and that credential being used.
func TestPoolTake_SkipsEntriesInsideTheSkewWindow(t *testing.T) {
	soon := Entry{ListID: "soon", Exp: time.Now().Add(entryExpirySkew / 2)}
	p := newExpiryTestPool(t, soon)

	if _, ok := p.take(); ok {
		t.Fatal("an entry expiring within the skew window must not be handed out")
	}
}

// A pool holding nothing but stale entries is empty for the caller, and must
// say so rather than returning one.
func TestPoolTake_AllExpiredReportsEmpty(t *testing.T) {
	p := newExpiryTestPool(t,
		Entry{ListID: "a", Exp: time.Now().Add(-time.Hour)},
		Entry{ListID: "b", Exp: time.Now().Add(-time.Minute)},
	)

	if _, ok := p.take(); ok {
		t.Fatal("want (Entry{}, false) when every entry is stale")
	}
	if p.size() != 0 {
		t.Fatalf("stale entries must be discarded: size=%d", p.size())
	}
	// And the caller must have been told to refill.
	select {
	case <-p.wake:
	default:
		t.Fatal("an emptied pool must signal a refill")
	}
}

// The status service sets `exp` at its discretion and may omit it. A zero
// Exp therefore means "no stated expiry", NOT "expired in year zero" -
// reading it the other way would discard every entry from such a service and
// spin the refill loop forever.
func TestPoolTake_ZeroExpiryIsNotExpired(t *testing.T) {
	p := newExpiryTestPool(t, Entry{ListID: "no-exp"})

	got, ok := p.take()
	if !ok {
		t.Fatal("an entry with no stated expiry must be usable")
	}
	if got.ListID != "no-exp" {
		t.Fatalf("got %q", got.ListID)
	}
}

// The expiry check has to cover Take's synchronous fallback too, not just
// the pooled path. An entry allocated on demand goes straight into a
// credential, so if AllocateExpiry or the service's own maximum lifetime is
// shorter than entryExpirySkew, every allocation is born inside the window
// and handing one back would issue a credential that outlives its status
// list.
func TestTake_FallbackRejectsAnEntryInsideTheSkewWindow(t *testing.T) {
	var allocations int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
			return
		}
		atomic.AddInt32(&allocations, 1)
		// Always allocates something already inside the skew window.
		exp := time.Now().Add(entryExpirySkew / 2).UTC().Format(time.RFC3339)
		_, _ = w.Write([]byte(`{"list_url":"https://status.example.org/lists/abc","index":1,"exp":"` + exp + `"}`))
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: 2 * time.Millisecond,
		TakeFallbackTimeout: 150 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.Take(context.Background()); err == nil {
		t.Fatal("Take must not return an entry that is already inside the expiry skew window")
	}
	if atomic.LoadInt32(&allocations) == 0 {
		t.Fatal("the fallback should have attempted an allocation")
	}
}

// TestTake_ReleasesAndStopsWhenEveryAllocationIsBornExpired is the leak
// case: a rejected entry has already been RESERVED on the service, so
// dropping it and retrying spends another remote VALID slot every attempt.
// The condition that causes it - AllocateExpiry or the service's maximum
// lifetime being shorter than the skew - is a configuration fact that does
// not change between attempts, so retrying can only burn slots until the
// timeout.
func TestTake_ReleasesAndStopsWhenEveryAllocationIsBornExpired(t *testing.T) {
	var allocations, releases int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
		case r.Method == http.MethodPatch:
			atomic.AddInt32(&releases, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			atomic.AddInt32(&allocations, 1)
			exp := time.Now().Add(entryExpirySkew / 2).UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(`{"list_url":"` + "https://status.example.org/lists/abc" + `","index":1,"exp":"` + exp + `"}`))
		}
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		// PoolSize 1, not 0: zero is defaulted to 50, and the background
		// refill would then be allocating alongside the path under test.
		PoolSize: 1, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: 2 * time.Millisecond,
		TakeFallbackTimeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.Take(context.Background()); err == nil {
		t.Fatal("Take must not return an entry inside the expiry skew window")
	}

	// One allocation from the background refill (PoolSize 1) and one from
	// Take's fallback, each released. What must NOT happen is unbounded
	// growth: before this fix the refill pushed born-expired entries, take()
	// discarded them and signalled another refill, and the loop never ended.
	//
	// The refill runs in its own goroutine, so its release lands after Take
	// has already returned. Wait for the counts to settle rather than
	// reading them straight away - a single unsynchronised read passes or
	// fails on timing, which is how the first version of this test passed
	// once and failed under -count.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&releases) == atomic.LoadInt32(&allocations) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	gotAlloc := atomic.LoadInt32(&allocations)
	gotRelease := atomic.LoadInt32(&releases)

	// A bound, not an exact count: the refill goroutine can be woken more
	// than once (start-up, plus take() signalling an empty pool), so two or
	// three allocations are both legitimate. What the fix has to guarantee
	// is that the number does not GROW - with the hot loop this test
	// measured 604 in one second, so any small bound separates the two.
	const bound = 10
	if gotAlloc > bound {
		t.Fatalf("allocated %d entries (bound %d); a configuration error that cannot change between attempts must not be retried into a loop", gotAlloc, bound)
	}
	if gotRelease != gotAlloc {
		t.Fatalf("allocated %d entries but released %d: every reserved entry that can never be issued must be handed back", gotAlloc, gotRelease)
	}
}

// An entry that expires in the pool is still ALLOCATED on the status
// service. Dropping it locally and saying nothing leaves a VALID,
// unreferenced index reserved to this issuer for good - and unlike the
// bounded restart loss the package comment documents, this accrues on
// every idle-then-refill cycle, so a quiet issuer eats list capacity for
// as long as it runs.
func TestPoolTake_QueuesExpiredEntriesForReclaim(t *testing.T) {
	stale := Entry{ListURL: "https://s.example/l/stale", ListID: "stale", Index: 7, Exp: time.Now().Add(-time.Minute)}
	fresh := Entry{ListURL: "https://s.example/l/fresh", ListID: "fresh", Index: 1, Exp: time.Now().Add(time.Hour)}
	p := newExpiryTestPool(t, fresh, stale)

	if _, ok := p.take(); !ok {
		t.Fatal("want the fresh entry")
	}

	p.mu.Lock()
	queued := append([]Entry(nil), p.stale...)
	p.mu.Unlock()

	if len(queued) != 1 {
		t.Fatalf("stale = %v, want the one expired entry queued for reclaim", queued)
	}
	if queued[0].Index != 7 || queued[0].ListURL != stale.ListURL {
		t.Errorf("queued %+v, want the expired entry itself - reclaim needs its list and index", queued[0])
	}

	// And the refill loop has to be woken, or the reclaim waits for the
	// next periodic tick even though the pool is otherwise healthy.
	select {
	case <-p.wake:
	default:
		t.Error("discarding a stale entry must signal the refill loop")
	}
}

// reclaim marks each queued entry INVALID on the service and empties the
// queue. Without this the queue is just a different place to leak.
func TestPoolReclaim_MarksQueuedEntriesInvalid(t *testing.T) {
	type patch struct {
		path string
		body string
	}
	var mu sync.Mutex
	var patches []patch

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
			return
		}
		// Only the status updates: the background refill goroutine New
		// starts is also talking to this server, and counting its
		// /allocate calls as reclaims would make this test pass or fail on
		// the loop's timing.
		if !strings.HasPrefix(r.URL.Path, "/status/") {
			_, _ = w.Write([]byte(`{"list_url":"` + r.Host + `/lists/x","index":1}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		patches = append(patches, patch{path: r.URL.Path, body: string(body)})
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: 2 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.pool.mu.Lock()
	c.pool.stale = []Entry{
		{ListURL: server.URL + "/lists/aaa", ListID: "aaa", Index: 3},
		{ListURL: server.URL + "/lists/bbb", ListID: "bbb", Index: 9},
	}
	c.pool.mu.Unlock()

	c.pool.reclaim(context.Background())

	mu.Lock()
	got := append([]patch(nil), patches...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("sent %d status updates, want one per queued entry: %+v", len(got), got)
	}
	for _, p := range got {
		if !strings.Contains(p.body, "INVALID") {
			t.Errorf("update body %q does not mark the slot INVALID", p.body)
		}
	}
	if !strings.Contains(got[0].path, "/aaa/3") || !strings.Contains(got[1].path, "/bbb/9") {
		t.Errorf("paths %q and %q do not name the queued list and index", got[0].path, got[1].path)
	}

	c.pool.mu.Lock()
	remaining := len(c.pool.stale)
	c.pool.mu.Unlock()
	if remaining != 0 {
		t.Errorf("stale = %d after reclaim, want the queue drained", remaining)
	}
}

// The PATCHes go out with the pool mutex RELEASED. Holding it across a
// network call would block every take() for the duration, which is the
// issuance path this whole package is arranged to keep clear - and a
// status service that merely responds slowly would stall issuance.
func TestPoolReclaim_DoesNotHoldTheLockDuringTheCall(t *testing.T) {
	release := make(chan struct{})
	inFlight := make(chan struct{})
	var once sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/status/") {
			_, _ = w.Write([]byte(`{"list_url":"` + r.Host + `/lists/x","index":1}`))
			return
		}
		// The test only means anything while the call is actually in
		// flight: without this it could check the lock before reclaim ever
		// took it, and pass against a version that holds it throughout.
		once.Do(func() { close(inFlight) })
		<-release // the update hangs until the test lets it finish
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: 2 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.pool.mu.Lock()
	c.pool.stale = []Entry{{ListURL: server.URL + "/lists/aaa", ListID: "aaa", Index: 1}}
	c.pool.entries = []Entry{{ListID: "usable", Exp: time.Now().Add(time.Hour)}}
	c.pool.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.pool.reclaim(context.Background())
	}()

	// Wait until the PATCH is actually in flight, then - and only then -
	// check that the pool is still usable.
	select {
	case <-inFlight:
	case <-time.After(5 * time.Second):
		close(release)
		<-done
		t.Fatal("the status update never reached the server")
	}

	if !c.pool.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("the pool mutex is held while a status update is in flight")
	}
	c.pool.mu.Unlock()

	if _, ok := c.pool.take(); !ok {
		t.Error("take() must still be served while a reclaim is in flight")
	}

	close(release)
	<-done
}

// The queue is bounded. A status service that refuses every PATCH is
// already leaking slots - that is the failure this bounds rather than
// fixes - and growing the queue without limit would trade a leak the
// service can see for memory it cannot.
func TestPoolQueueStale_DropsTheOldestWhenFull(t *testing.T) {
	p := newExpiryTestPool(t)

	p.mu.Lock()
	for i := range maxStaleBacklog + 5 {
		p.queueStaleLocked(Entry{ListID: "l", Index: uint64(i)})
	}
	queued := append([]Entry(nil), p.stale...)
	p.mu.Unlock()

	if len(queued) != maxStaleBacklog {
		t.Fatalf("stale = %d, want it capped at %d", len(queued), maxStaleBacklog)
	}
	if queued[0].Index != 5 {
		t.Errorf("oldest kept entry has index %d, want 5 - the first five should have been dropped", queued[0].Index)
	}
	if queued[len(queued)-1].Index != uint64(maxStaleBacklog+4) {
		t.Errorf("newest kept entry has index %d, want the most recent", queued[len(queued)-1].Index)
	}
}
