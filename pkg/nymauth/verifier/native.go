package verifier

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrNativeNotBuilt is what every native entry point returns in a build
// without the "zknative" tag, which is every default build of this repo
// (CGO_ENABLED=0, fully static). See native_cgo.go and native_stub.go.
var ErrNativeNotBuilt = errors.New("nymauth: this binary was built without the zknative tag, so no nym_auth proof can be checked")

// CircuitParams are the catalog descriptor's parameters for a nym_auth
// circuit build, passed to the native loader alongside the artifact.
//
// The loader checks the artifact against its own allowlist entry - its
// length, its SHA-256 and these parameters - and refuses anything else
// before parsing it. They are not advisory.
type CircuitParams struct {
	BlockEncHash uint32
	BlockEncSig  uint32
	// HashCircuitID and SigCircuitID are the descriptor's circuit ids,
	// hex as the catalog writes them.
	HashCircuitID string
	SigCircuitID  string
}

// coordinateBytes is the width of a P-256 coordinate, which is how the
// circuits take Q: big-endian, fixed width, never minimally encoded.
const coordinateBytes = 32

// NativeRequest is Request flattened to exactly what the nym_auth C ABI
// takes (NymAuthCRequest in zk_cred_longfellow_nymauth.h).
//
// Separate from Request, and derived rather than built, for two
// reasons. The mapping is testable in a build without the native
// library, which is where most of the ways to get it wrong live; and
// the ABI's shape is the ABI's, not the request's - today it has one
// slot per age bound and no general predicate vector, and Request is
// deliberately not written that way (see functions.go).
type NativeRequest struct {
	IssuerKeyX, IssuerKeyY [coordinateBytes]byte
	Time                   string
	Earliest, Cutoff       string
	ChallengeDigest        [32]byte
	VerifierInput          [32]byte
	TranscriptSeed         []byte
}

// Native flattens a checked request for the native verifier.
//
// It refuses any predicate the ABI has no slot for. The C request
// carries an age window and nothing else, so a function the circuits
// would evaluate but this ABI cannot carry has to fail here: passing
// the request anyway would check the holder's proof against a statement
// missing one of the verifier's conditions, and report it as verified.
func (r Request) Native() (NativeRequest, error) {
	if err := r.Check(); err != nil {
		return NativeRequest{}, err
	}

	timeStr, err := r.TimeString()
	if err != nil {
		return NativeRequest{}, err
	}

	e2, err := r.E2()
	if err != nil {
		return NativeRequest{}, err
	}

	earliest, cutoff := NoLowerBound, NoUpperBound
	for _, input := range r.Inputs {
		if input.FunctionID != FunctionAgeCheck {
			return NativeRequest{}, fmt.Errorf(
				"nymauth: function %q has no slot in the nym_auth C ABI, which carries an age window and nothing else; verifying without it would check a statement missing one of this request's conditions",
				input.FunctionID)
		}
		earliest = string(input.Values[InputEarliest])
		cutoff = string(input.Values[InputCutoff])
	}

	native := NativeRequest{
		Time:            timeStr,
		Earliest:        earliest,
		Cutoff:          cutoff,
		ChallengeDigest: e2,
		VerifierInput:   r.VerifierInput,
		TranscriptSeed:  r.SessionTranscript,
	}
	if err := fillCoordinate(native.IssuerKeyX[:], r.IssuerKey.X); err != nil {
		return NativeRequest{}, fmt.Errorf("nymauth: issuer key x: %w", err)
	}
	if err := fillCoordinate(native.IssuerKeyY[:], r.IssuerKey.Y); err != nil {
		return NativeRequest{}, fmt.Errorf("nymauth: issuer key y: %w", err)
	}
	return native, nil
}

// fillCoordinate writes v big-endian, left-padded, into dst.
//
// FillBytes rather than Bytes: a coordinate whose leading byte is zero
// encodes one byte shorter, and the circuits read a fixed 32. Passing
// the short form would shift every byte of Q by one and verify against
// a different key - which fails, but as a bad proof rather than as the
// encoding mistake it is. FillBytes panics on a value too wide for dst,
// so the width is checked first.
func fillCoordinate(dst []byte, v *big.Int) error {
	if v.Sign() < 0 {
		return fmt.Errorf("negative")
	}
	if byteLen := (v.BitLen() + 7) / 8; byteLen > len(dst) {
		return fmt.Errorf("%d bytes wide; a P-256 coordinate is at most %d", byteLen, len(dst))
	}
	v.FillBytes(dst)
	return nil
}
