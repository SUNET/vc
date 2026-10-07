//go:build zknative

package mdoc

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
)

// WarmVegaVerifierKeys downloads every currently-active Vega circuit's
// verifier key into the local store, so no holder pays for it.
//
// Without this the first Vega presentation on each instance paid the
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
		if role, _ := c.ParamString(vegaRoleParam); role != vegaRoleProver {
			continue
		}
		// Every error is recorded and none stops the loop: one circuit
		// revision the catalog cannot serve should not deny the others
		// the warm-up they were going to get.
		if _, err := getOrLoadVegaVerifierKey(ctx, c.ID, sources); err != nil {
			result.Failed[c.ID] = err
			continue
		}
		result.Warmed = append(result.Warmed, c.ID)
	}

	return result, nil
}
