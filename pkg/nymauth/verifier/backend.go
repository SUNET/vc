package verifier

import (
	"crypto/subtle"
	"fmt"
)

// Backend is one proof system's nym_auth verifier.
//
// Both systems answer the same question - does this proof hold for the
// statement this Verifier named, and what pseudonym does it reveal -
// so the dispatch holds one of these and does not care which system is
// behind it. What differs is everything below the interface: how the
// circuit is loaded, and what the native ABI takes.
//
// The returned pseudonym is the ONLY one a caller may act on. The
// value in the holder's response is a claim until a proof has been
// checked against it, and that happens here.
type Backend interface {
	// Verify checks proof against req and the pseudonym the holder
	// claimed, and returns the pseudonym this verifier may use.
	Verify(req Request, claimed [32]byte, proof []byte) ([32]byte, error)

	// Close releases the loaded circuit.
	Close() error
}

// Compile-time proof that both systems satisfy it, in every build. The
// stub pair carries the same methods, so a build without the native
// libraries fails here too if one of them drifts.
var (
	_ Backend = (*NativeVerifier)(nil)
	_ Backend = (*VegaVerifier)(nil)
)

// ErrPseudonymMismatch is a proof that verifies for a different
// pseudonym than the holder claimed.
//
// Separate from a proof that does not verify at all, because it is a
// different fact: the proof is sound, and the response's results do
// not match what it proves.
var ErrPseudonymMismatch = fmt.Errorf("nymauth: the proof is valid but reveals a different pseudonym than the response claimed")

// checkClaimed compares a revealed pseudonym with the claimed one in
// constant time.
//
// Needed by a backend whose ABI REVEALS the pseudonym rather than
// taking the claimed value and comparing internally - Vega does the
// former, Longfellow the latter. Constant time because the comparison
// is between a secret-derived identifier and a value an attacker
// supplies, and a byte-at-a-time answer would let one be searched for.
func checkClaimed(revealed, claimed [32]byte) error {
	if subtle.ConstantTimeCompare(revealed[:], claimed[:]) != 1 {
		return ErrPseudonymMismatch
	}
	return nil
}
