//go:build zknative

package mdoc

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
)

// WarmVegaVerifierKeys downloads every currently-active Vega circuit's
// verifier key into the local store.
//
// BEST-EFFORT latency reduction, not a guarantee: the caller runs this in
// the background and the server is ready before it finishes, so a
// presentation arriving during the warm-up either joins the in-flight load
// for its circuit - still better than starting its own - or loads one this
// has not reached yet, exactly as before. What it removes is the
// steady-state case, where an instance that has been up a minute already
// holds every active circuit.
//
// Without it the first Vega presentation on each instance paid the
// download and decompression of a ~100MB artifact INLINE - while the holder
// waited at the very end of a presentation, after selecting credentials and
// signing. With N instances that is N unlucky users, load balancing picks
// which ones, and every restart and rolling deploy re-picks them
// (SUNET/vc#656). Nothing about it was visible as an error; it looked like
// a slow wallet.
//
// Keyed by PROVER id, because that is what a wallet names in its proof and
// therefore what the store is keyed by; the verifier sibling is resolved
// the same way a live request resolves it.
//
// Only ACTIVE circuits. A deprecated revision still presents - wallets
// update on their own schedule - and still loads lazily on first use; what
// warming every revision ever published would do is grow without bound for
// the sake of a request that may never come.
//
// Returns an error only when the catalog could not be consulted at all. An
// individual key that fails to warm is reported in the result and left to
// load lazily, which is what used to happen to all of them.
func WarmVegaVerifierKeys(ctx context.Context, sources []string) (VegaWarmResult, error) {
	result := VegaWarmResult{Failed: map[string]error{}}

	client := zkcircuit.NewClient(sources...)
	manifest, err := client.FetchManifest(ctx)
	if err != nil {
		return result, fmt.Errorf("fetching the circuit manifest to pre-warm Vega verifier keys: %w", err)
	}

	for i := range manifest.Circuits {
		c := &manifest.Circuits[i]
		if !c.Published || c.Status != vegaStatusActive {
			continue
		}
		// System as well as role. "role" is a generic params key and
		// another proof system adopting it would have its artifacts
		// downloaded into a store sized for Vega keys, evicting the real
		// ones - a cache that quietly stops holding what it is for, which
		// shows up as latency and never as an error.
		if !isVegaCatalogSystem(c.System) {
			continue
		}
		if role, _ := c.ParamString(vegaRoleParam); role != vegaRoleProver {
			continue
		}
		// Every error is recorded and none stops the loop: one circuit
		// revision the catalog cannot serve should not deny the others
		// the warm-up they were going to get.
		_, release, err := getOrLoadVegaVerifierKey(ctx, c.ID, sources)
		if err != nil {
			result.Failed[c.ID] = err
			continue
		}
		// Warming holds no pin: nothing is about to read the file, and a
		// pin held past this loop would exempt the key from eviction for
		// the life of the process.
		release()
		result.Warmed = append(result.Warmed, c.ID)
	}

	return result, nil
}
