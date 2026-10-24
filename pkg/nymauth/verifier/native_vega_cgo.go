//go:build zknative

package verifier

import (
	"fmt"

	"github.com/SUNET/vc/pkg/nymauth/verifier/zknative_vega"
)

// VegaVerifier checks nym_auth proofs through zk-cred-vega's C ABI.
// Real in a build with the "zknative" tag; see native_vega_stub.go for
// what every other build gets.
type VegaVerifier struct {
	v *zknative_vega.Verifier
}

// NewVegaVerifier derives the verifier keys from a decompressed R1CS
// shapes artifact.
//
// Deriving is the expensive step here, and expensive in a different way
// from Longfellow's: Vega has no precomputed verifier key to load, it
// builds roughly 12.5 MB of one from the shapes every time. Keep the
// result and reuse it across verifications. Safe for concurrent use.
func NewVegaVerifier(shapes []byte) (*VegaVerifier, error) {
	v, err := zknative_vega.NewVerifier(shapes)
	if err != nil {
		return nil, err
	}
	return &VegaVerifier{v: v}, nil
}

// Close releases the keys.
func (n *VegaVerifier) Close() error {
	if n == nil || n.v == nil {
		return nil
	}
	return n.v.Close()
}

// Verify checks proof against req and the pseudonym the holder
// claimed, and returns the pseudonym the caller may use.
//
// The Vega ABI REVEALS the pseudonym instead of taking the claimed one
// and comparing inside the circuit, which is the one place the two
// systems differ at this level. So the comparison happens here, in
// constant time, and a proof that is sound for a different pseudonym
// is ErrPseudonymMismatch rather than a verification failure - the
// same distinction Longfellow's ABI draws internally.
func (n *VegaVerifier) Verify(req Request, claimed [32]byte, proof []byte) ([32]byte, error) {
	if n == nil || n.v == nil {
		return [32]byte{}, fmt.Errorf("nymauth: the Vega verifier is closed or nil")
	}
	native, err := req.Native()
	if err != nil {
		return [32]byte{}, err
	}

	// TranscriptSeed is deliberately not passed on. It is Longfellow's
	// alone: the Vega statement binds the transcript through e2, which
	// req.Native() has already derived, and this ABI has no slot for
	// the transcript itself.
	revealed, err := n.v.Verify(zknative_vega.Statement{
		IssuerKeyX:      native.IssuerKeyX[:],
		IssuerKeyY:      native.IssuerKeyY[:],
		Time:            native.Time,
		Earliest:        native.Earliest,
		Cutoff:          native.Cutoff,
		ChallengeDigest: native.ChallengeDigest[:],
		VerifierInput:   native.VerifierInput[:],
	}, proof)
	if err != nil {
		return [32]byte{}, err
	}
	if err := checkClaimed(revealed, claimed); err != nil {
		return [32]byte{}, err
	}
	return revealed, nil
}
