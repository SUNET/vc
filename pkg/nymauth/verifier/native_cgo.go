//go:build zknative

package verifier

import (
	"fmt"

	"github.com/SUNET/vc/pkg/nymauth/verifier/zknative"
)

// NativeVerifier checks nym_auth proofs through zk-cred-longfellow's C
// ABI. Real in a build with the "zknative" tag; see native_stub.go for
// what every other build gets, and pkg/nymauth/verifier/zknative for
// the binding itself.
type NativeVerifier struct {
	v *zknative.Verifier
}

// NewNativeVerifier loads a decompressed nym_auth circuit artifact.
//
// Loading is the expensive step, so keep the result and reuse it across
// verifications rather than loading per proof. Safe for concurrent use.
func NewNativeVerifier(circuit []byte, params CircuitParams) (*NativeVerifier, error) {
	v, err := zknative.NewVerifier(circuit, zknative.Params{
		BlockEncHash:  params.BlockEncHash,
		BlockEncSig:   params.BlockEncSig,
		HashCircuitID: params.HashCircuitID,
		SigCircuitID:  params.SigCircuitID,
	})
	if err != nil {
		return nil, err
	}
	return &NativeVerifier{v: v}, nil
}

// Close releases the circuit handle.
func (n *NativeVerifier) Close() error {
	if n == nil {
		return nil
	}
	return n.v.Close()
}

// Verify checks proof against req and the pseudonym the holder claimed,
// and returns the pseudonym the caller may use.
//
// Callers must use the RETURNED pseudonym and never the one they passed
// in, even though the two are equal whenever this returns nil. The
// claimed value arrived in the holder's response; it becomes an
// identifier this verifier may act on only once a proof has been
// checked against it, and the return value is the only place that has
// happened.
func (n *NativeVerifier) Verify(req Request, claimed [32]byte, proof []byte) ([32]byte, error) {
	if n == nil || n.v == nil {
		return [32]byte{}, fmt.Errorf("nymauth: the native verifier is closed or nil")
	}
	native, err := req.Native()
	if err != nil {
		return [32]byte{}, err
	}
	return n.v.Verify(zknative.Request{
		IssuerKeyX:      native.IssuerKeyX[:],
		IssuerKeyY:      native.IssuerKeyY[:],
		Time:            native.Time,
		Earliest:        native.Earliest,
		Cutoff:          native.Cutoff,
		ChallengeDigest: native.ChallengeDigest[:],
		VerifierInput:   native.VerifierInput[:],
		TranscriptSeed:  native.TranscriptSeed,
	}, claimed[:], proof)
}
