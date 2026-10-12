//go:build !zknative

package mdoc

import "context"

// WarmVegaVerifierKeys is a no-op without the "zknative" build tag: this
// build cannot verify a Vega proof at all (see zk_native_stub.go), so there
// is nothing a downloaded verifier key would ever be used for. Reported as
// an empty result rather than an error - the caller asked to warm a cache
// that correctly holds nothing, which is not a failure.
func WarmVegaVerifierKeys(_ context.Context, _ []string) (VegaWarmResult, error) {
	return VegaWarmResult{Failed: map[string]error{}}, nil
}
