package statusserviceclient

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Entry is one pre-allocated status-list slot: a (list_url, index) pair
// returned by POST /allocate, not yet embedded in any issued credential.
type Entry struct {
	// ListURL is the full verifier-facing Status List Token URL, exactly as
	// returned by the status service - this is what belongs in a
	// credential's `status.status_list.uri` claim.
	ListURL string
	// ListID is ListURL's final path segment, extracted client-side since
	// the allocate response does not return it separately. It is what
	// PATCH /status/{listID}/{idx} needs, and is otherwise not meaningful
	// on its own.
	ListID string
	// Index is this credential's position within the list - the
	// `status.status_list.idx` claim value.
	Index uint64
	// Exp is the expiration the status service actually used for this
	// entry (its own configured maximum, unless Config.AllocateExpiry
	// asked for something else).
	Exp time.Time
}

// pool holds a client's local cache of pre-allocated Entry values and keeps
// it topped up in the background. See the package doc comment for the
// design rationale (why pool-based, why in-memory-only, why low-water-mark
// plus periodic refill).
type pool struct {
	c *Client

	mu      sync.Mutex
	entries []Entry

	// wake is signalled (non-blocking) whenever the pool drops to or below
	// LowWaterMark, to trigger an immediate refill attempt instead of
	// waiting for the next periodic tick.
	wake chan struct{}
}

func newPool(c *Client) *pool {
	return &pool{
		c:    c,
		wake: make(chan struct{}, 1),
	}
}

// take pops one usable entry from the pool, returning (Entry{}, false) if
// none is left.
//
// Entries are discarded rather than returned once their Exp has passed. The
// pool is a cache of slots the status service has already committed to, and
// nothing refreshes them while they sit here - so on a quiet issuer an entry
// can go stale before it is ever used, and handing it out would put an
// already-expired status_list reference into an issued credential, where a
// verifier resolving it is the one who finds out.
//
// This pops from the end, so the oldest entries are the last to be reached
// and the most likely to have expired; discarding is what stops them
// accumulating at the bottom of the slice forever.
func (p *pool) take() (Entry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var e Entry
	found := false
	for len(p.entries) > 0 {
		candidate := p.entries[len(p.entries)-1]
		p.entries = p.entries[:len(p.entries)-1]
		if p.c.expired(candidate) {
			continue
		}
		e = candidate
		found = true
		break
	}

	if !found {
		// Signal a refill: the pool is empty, or held nothing but stale
		// entries, and either way it needs topping up.
		select {
		case p.wake <- struct{}{}:
		default:
		}
		return Entry{}, false
	}

	if len(p.entries) <= p.c.cfg.LowWaterMark {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
	return e, true
}

// size returns the current pool size (for tests/observability).
func (p *pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// push appends freshly allocated entries.
func (p *pool) push(entries ...Entry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, entries...)
}

// needed returns how many more entries are needed to reach PoolSize.
func (p *pool) needed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.c.cfg.PoolSize - len(p.entries)
	if n < 0 {
		return 0
	}
	return n
}

// run is the background refill loop: wakes on a low-water-mark signal or a
// periodic tick, tops the pool back up to PoolSize (retrying indefinitely,
// with capped backoff, per entry - see Client.backgroundRetry), and stops
// when stopCh is closed. One refill pass allocates entries one at a time
// rather than in a single batched call, since the status service's
// /allocate endpoint has no batch form; each individual allocate call still
// gets its own retry-with-backoff.
func (p *pool) run(stopCh <-chan struct{}) {
	ctx, cancel := contextFromStop(stopCh)
	defer cancel()

	p.refill(ctx)

	ticker := time.NewTicker(p.c.cfg.RefillInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-p.wake:
			p.refill(ctx)
		case <-ticker.C:
			p.refill(ctx)
		}
	}
}

// refill allocates entries until the pool reaches PoolSize or ctx is
// cancelled (Close was called). A run of allocation failures (status
// service down) stops this pass early - the next wake or tick tries again
// - rather than spinning tightly; retry() inside allocateOnce's caller
// already backs off within a single allocation attempt's own retry budget,
// but backgroundRetry has no maxElapsed, so a single stuck allocate call
// legitimately keeps retrying (with growing, capped backoff) across the
// whole gap until it succeeds or ctx is cancelled - it does not return
// control to this loop meanwhile. That is intentional: it is exactly the
// "make every effort to recover" behaviour requested, applied to filling
// the pool rather than to a single credential's issuance.
func (p *pool) refill(ctx context.Context) {
	for p.needed() > 0 {
		var entry Entry
		err := retry(ctx, p.c.backgroundRetry(), func(ctx context.Context) error {
			e, err := p.c.allocateOnce(ctx)
			if err != nil {
				return err
			}
			// An entry born inside the expiry skew must not go into the
			// pool. take() would discard it on the way out and signal
			// another refill, and since the cause - AllocateExpiry or the
			// service's own maximum lifetime being shorter than the skew -
			// is a configuration fact, every replacement is born the same
			// way. That is a hot loop consuming a remote VALID slot per
			// iteration, for as long as the process runs.
			//
			// backgroundRetry has no maxElapsed, so this MUST be permanent
			// or the retry itself would spin on it.
			if p.c.expired(e) {
				p.c.releaseUnusable(ctx, e)
				return permanent(fmt.Errorf("status service allocated an entry expiring at %s, within the %s skew: check AllocateExpiry against the service's maximum lifetime",
					e.Exp.Format(time.RFC3339), entryExpirySkew))
			}
			entry = e
			return nil
		})
		if err != nil {
			// ctx cancelled (Close), or a permanent error (e.g. our own
			// key is no longer trusted). Either way, stop this pass; the
			// next wake/tick will try again for a transient cause, and
			// Close will have torn everything down for the ctx-cancelled
			// case.
			if ctx.Err() != nil {
				return
			}
			p.c.log.Error(err, "pool refill: permanently failed to allocate a status-list entry; will retry on the next cycle")
			return
		}
		p.push(entry)
	}
}

// contextFromStop adapts a <-chan struct{} "stop" signal (as Client uses
// throughout, to match its own Close() shape) to a context.Context, for the
// retry() helper which is expressed in terms of context.
func contextFromStop(stopCh <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// Take returns one pre-allocated Entry, immediately if the pool is
// non-empty. If the pool is empty, it falls back to one bounded, retried
// synchronous allocation (bounded by Config.TakeFallbackTimeout) so a cold
// start or a burst that outpaces the background refill still works. If that
// fallback also fails, it returns ErrPoolExhausted wrapping the underlying
// cause; the caller (internal/issuer/apiv1) decides what to do next per its
// configured degraded mode.
func (c *Client) Take(ctx context.Context) (Entry, error) {
	if e, ok := c.pool.take(); ok {
		return e, nil
	}

	var entry Entry
	err := retry(ctx, c.foregroundRetry(), func(ctx context.Context) error {
		e, err := c.allocateOnce(ctx)
		if err != nil {
			return err
		}
		// The same check pool.take applies, for the same reason: an entry
		// too close to expiry must not reach a credential. A freshly
		// allocated one can still fail it - if AllocateExpiry or the
		// service's own maximum lifetime is shorter than entryExpirySkew,
		// every allocation is born inside the window - so this is retried
		// rather than silently accepted, and a caller that keeps failing
		// gets a configuration error rather than an unusable reference.
		if c.expired(e) {
			// The entry is already RESERVED on the service. Dropping it and
			// retrying consumes another remote VALID slot every attempt,
			// and the condition that caused it - AllocateExpiry or the
			// service's own maximum lifetime being shorter than the skew -
			// is a configuration fact that will not change between
			// attempts. So hand this one back and stop: at most one slot is
			// spent, and the caller gets the configuration error straight
			// away instead of after the whole retry budget.
			c.releaseUnusable(ctx, e)
			return permanent(fmt.Errorf("status service allocated an entry expiring at %s, within the %s skew: check AllocateExpiry against the service's maximum lifetime",
				e.Exp.Format(time.RFC3339), entryExpirySkew))
		}
		entry = e
		return nil
	})
	if err != nil {
		return Entry{}, joinPoolExhausted(err)
	}
	return entry, nil
}

func joinPoolExhausted(cause error) error {
	return &poolExhaustedError{cause: cause}
}

type poolExhaustedError struct{ cause error }

func (e *poolExhaustedError) Error() string {
	return ErrPoolExhausted.Error() + ": " + e.cause.Error()
}
func (e *poolExhaustedError) Unwrap() []error { return []error{ErrPoolExhausted, e.cause} }

// releaseUnusable marks an entry INVALID that was allocated but can never be
// issued, so the slot is not left reserved-but-unused on the service.
//
// Best-effort and one-shot on purpose: this runs on a path that is already
// failing, and retrying the release would spend the caller's remaining time
// budget on cleanup rather than on the error it is about to return. A
// release that does not land costs one leaked slot, which is the same cost
// as not trying - never worse.
func (c *Client) releaseUnusable(ctx context.Context, e Entry) {
	listID, err := ListIDFromURL(e.ListURL)
	if err != nil {
		c.log.Error(err, "cannot determine the list ID to release an unusable status entry", "list_url", e.ListURL)
		return
	}
	if err := c.setStatusOnce(ctx, listID, e.Index, StatusInvalid); err != nil {
		c.log.Error(err, "could not release an unusable status entry; the slot stays reserved on the service",
			"list_id", listID, "index", e.Index)
	}
}
