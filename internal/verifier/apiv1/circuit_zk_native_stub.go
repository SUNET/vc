//go:build !zknative

package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// This file is what every default build of this repo gets: no cgo, no
// zk-cred-longfellow, and so no way to check a nym_auth proof. See
// circuit_zk_native_cgo.go for the real implementation, opt-in via
// `-tags zknative` - the same shape as pkg/mdoc's zk_native_stub.go /
// zk_native_cgo.go pair, and for the same reason: the default
// vc-verifier build is CGO_ENABLED=0 and fully static.
//
// It REFUSES rather than returning a verified-looking zero value.
// Everything upstream - the request's own checks, the response's
// shape, its binding to the offer, the circuit this verifier allows -
// is real and has already run by the time this is called, so a nil
// error here would hand all of that back as a successful verification
// of a proof nothing looked at.

// verifyCircuitZkPresentation always fails in this build.
func (c *Client) verifyCircuitZkPresentation(
	_ context.Context,
	_ openid4vp.CircuitZkPresentation,
	_ circuitZkSession,
	_ []openid4vp.ReqItem,
	_ any,
) (map[string][]byte, error) {
	return nil, ErrCircuitZkNotBuilt
}
