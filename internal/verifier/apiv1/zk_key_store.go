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
	go c.prewarmVegaKeys(context.Background(), c.cfg.Verifier.ZkCircuits.Sources)
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
