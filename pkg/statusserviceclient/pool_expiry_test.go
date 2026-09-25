package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newExpiryTestPool builds a pool without starting any background loop -
// take() is pure enough to test on its own, and a refill goroutine would
// race the assertions.
func newExpiryTestPool(t *testing.T, entries ...Entry) *pool {
	t.Helper()
	c := &Client{cfg: Config{PoolSize: 8, LowWaterMark: 1}}
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
		IssuerID: "https://issuer.example.org", Key: key,
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
