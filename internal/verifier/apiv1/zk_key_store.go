package apiv1

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
)

// zkPrewarmTimeout bounds the background warm-up. Several ~100MB artifacts
// over a link nobody has measured, so generous - but not unbounded, since a
// goroutine blocked on a hung catalog for the life of the process is a leak
// wearing a cache's clothes.
const zkPrewarmTimeout = 15 * time.Minute

// configureVegaKeyStore applies verifier.zk_key_cache and, unless told not
// to, starts the background pre-warm.
//
// Both knobs are process-wide setters rather than fields on
// ZkVerifierConfig, and that is forced rather than chosen: NewZkHandler is
// called INSIDE the request loop, so anything hung off its config would be
// built and discarded once per presentation.
//
// The warm-up is BEST-EFFORT latency reduction, not a guarantee. It runs in
// the background, so the HTTP server becomes ready while downloads are
// still going: a presentation arriving in that window either joins the
// in-flight load for its circuit - which is still better than starting its
// own - or loads one the warm-up has not reached yet, exactly as it did
// before. What it removes is the steady-state case, where every instance
// that has been up for a minute already holds every active circuit.
func (c *Client) configureVegaKeyStore() {
	cache := c.cfg.Verifier.ZkKeyCache

	mdoc.SetVegaVerifierKeyCacheDir(cache.Dir)
	if cache.MaxBytes > 0 {
		mdoc.SetVegaVerifierKeyCacheBytes(int(cache.MaxBytes))
	}

	if !model.BoolVal(cache.Prewarm, true) {
		c.log.Debug("Vega verifier-key pre-warm disabled by configuration")
		return
	}

	// Detached from the caller's context on purpose: New's ctx belongs to
	// startup and this outlives it. The warm-up never blocks startup -
	// several hundred MB of downloads before the first health check would
	// trade one holder's latency for every holder's.
	//
	// Cancellable and awaitable all the same: a download finishing after
	// the store has been torn down would otherwise recreate its directory
	// and leave key files behind after the process exited.
	ctx, cancel := context.WithCancel(context.Background())
	c.zkPrewarmCancel = cancel
	c.zkPrewarmDone = make(chan struct{})

	go func() {
		defer close(c.zkPrewarmDone)
		c.prewarmVegaKeys(ctx, c.cfg.Verifier.ZkCircuits.Sources)
	}()
}

// StopVegaPrewarm cancels the background warm-up and waits for it to
// finish, so a shutdown can tear the key store down without racing a
// download into recreating it. Safe to call when no warm-up was started.
func (c *Client) StopVegaPrewarm(ctx context.Context) {
	if c == nil || c.zkPrewarmCancel == nil {
		return
	}
	c.zkPrewarmCancel()

	select {
	case <-c.zkPrewarmDone:
	case <-ctx.Done():
		// The store refuses writes once closed, so a warm-up that outlives
		// this cannot recreate the directory - it just will not be waited
		// for.
		c.log.Info("gave up waiting for the Vega verifier-key warm-up to stop")
	}
}

// prewarmVegaKeys warms the store and reports what happened. Never fatal:
// a key that does not warm loads lazily on first use, which is what used to
// happen to every one of them.
func (c *Client) prewarmVegaKeys(ctx context.Context, sources []string) {
	ctx, cancel := context.WithTimeout(ctx, zkPrewarmTimeout)
	defer cancel()

	started := time.Now()
	result, err := mdoc.WarmVegaVerifierKeys(ctx, sources)
	if err != nil {
		c.log.Error(err, "zk_vega_prewarm_failed", "sources", sources)
		return
	}

	for id, failure := range result.Failed {
		c.log.Error(failure, "zk_vega_prewarm_circuit_failed", "circuit_id", id)
	}

	// Debug when there was nothing to do: a build without the zknative tag
	// warms nothing by design, and so does a catalog with no active Vega
	// circuit. Neither is worth a line in every verifier's startup log.
	if len(result.Warmed) == 0 && len(result.Failed) == 0 {
		c.log.Debug("no Vega verifier keys to pre-warm")
		return
	}

	c.log.Info("Vega verifier keys pre-warmed",
		"warmed", len(result.Warmed), "failed", len(result.Failed),
		"circuit_ids", result.Warmed, "took", time.Since(started).String())
}
