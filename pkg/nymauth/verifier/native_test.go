package verifier

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The flattened request is what the circuits are actually checked
// against, so every field of it has to be the request's - not a
// default, not a truncation, and not a silently dropped condition.
func TestNativeRequestCarriesTheRequest(t *testing.T) {
	r := testRequest(t)
	native, err := r.Native()
	require.NoError(t, err)

	assert.Equal(t,
		"7eea0f8e073961c3e82e9562e0f79edaa66dbfc17eaf0ac0596a987733516dd9",
		hex.EncodeToString(native.ChallengeDigest[:]),
		"challenge-vectors.json, verifier 1")
	assert.Equal(t, r.SessionTranscript, native.TranscriptSeed)
	assert.Equal(t, r.VerifierInput, native.VerifierInput)
	assert.Len(t, native.Time, 20, "the circuits take T as 20 ASCII bytes")

	// The fixture asks for a birth date at or after 2000-01-01, so the
	// window is bounded below and open above.
	assert.Equal(t, "2000-01-01", native.Earliest)
	assert.Equal(t, NoUpperBound, native.Cutoff)
}

// A request with no predicate is a pure pseudonym proof, and the ABI
// spells "no bound" with its sentinels rather than with an empty
// string, which would be a date the circuits cannot read.
func TestNativeRequestWithoutAPredicateDisablesBothBounds(t *testing.T) {
	r := testRequest(t)
	r.Inputs = nil
	native, err := r.Native()
	require.NoError(t, err)
	assert.Equal(t, NoLowerBound, native.Earliest)
	assert.Equal(t, NoUpperBound, native.Cutoff)
}

// Q is big-endian and FIXED width. A coordinate with leading zero bytes
// encodes shorter, and writing that short form would shift every byte
// of the key.
func TestNativeRequestPadsTheIssuerCoordinates(t *testing.T) {
	r := testRequest(t)
	r.IssuerKey.X = big.NewInt(1)
	native, err := r.Native()
	require.NoError(t, err)
	assert.Equal(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		hex.EncodeToString(native.IssuerKeyX[:]))
}

// A coordinate too wide for the fixed field would panic inside
// FillBytes, so it is refused with its width named.
func TestNativeRequestRefusesAnOverWideCoordinate(t *testing.T) {
	r := testRequest(t)
	r.IssuerKey.X = new(big.Int).Lsh(big.NewInt(1), 256)
	_, err := r.Native()
	assert.ErrorContains(t, err, "33 bytes wide")
}

// The C request has one age window and no general predicate vector.
// A function it cannot carry has to stop the verification: passing the
// request anyway would check the proof against a statement missing one
// of this verifier's conditions and report that as verified.
func TestNativeRequestRefusesAPredicateTheABICannotCarry(t *testing.T) {
	const other = "test.native_has_no_slot"
	require.NoError(t, Register(Function{ID: other, Inputs: []string{"value"}}))

	r := testRequest(t)
	r.Inputs = []CircuitInput{{FunctionID: other, Values: map[string][]byte{"value": []byte("x")}}}
	r.SupportedFunctions = []string{other}

	_, err := r.Native()
	assert.ErrorContains(t, err, "no slot in the nym_auth C ABI")
}

// Native checks the request itself, so a caller cannot reach the
// native boundary by skipping Check.
func TestNativeRequestChecksTheRequest(t *testing.T) {
	r := testRequest(t)
	r.IssuerKey = nil
	_, err := r.Native()
	assert.ErrorContains(t, err, "never from the proof")
}

// The transcript-seed bound is THIS library's, so it is enforced where
// the request is flattened for it - not in Request.Check, which must
// keep accepting a request some other circuit can verify.
func TestNativeRequestEnforcesTheLibrarysTranscriptBound(t *testing.T) {
	short := testRequest(t)
	short.SessionTranscript = []byte{0x83, 0xf6, 0xf6, 0x68, 'h', 'a', 'n', 'd', 'o', 'v', 'e', 'r'}
	require.NoError(t, short.Check(), "a short transcript is a valid request")
	_, err := short.Native()
	assert.ErrorContains(t, err, "this circuit library takes 32 to 65536")

	// A WELL-FORMED transcript that is simply too long: [null, null,
	// <a long byte string>]. Padding with zero bytes would be refused
	// by the shape check first and would not exercise this bound at
	// all.
	payload := make([]byte, MaxTranscriptBytes)
	long := testRequest(t)
	long.SessionTranscript = append([]byte{0x83, 0xf6, 0xf6, 0x5a,
		byte(len(payload) >> 24), byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)),
	}, payload...)
	require.NoError(t, long.Check(), "it is well-formed, just too long for this library")
	_, err = long.Native()
	assert.ErrorContains(t, err, "this circuit library takes 32 to 65536")
}
