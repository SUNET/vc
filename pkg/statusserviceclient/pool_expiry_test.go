package statusserviceclient

import (
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
