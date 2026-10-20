package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRequest(t *testing.T) Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bounds, err := AgeCheck{GE: "2000-01-01"}.Bounds()
	require.NoError(t, err)

	input, err := VerifierInput("verifier.example")
	require.NoError(t, err)

	transcript, err := MdocSessionTranscript("https://verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", nil)
	require.NoError(t, err)

	return Request{
		IssuerKey:          &key.PublicKey,
		Now:                time.Now(),
		Inputs:             []CircuitInput{bounds.CircuitInput()},
		SupportedFunctions: []string{FunctionAgeCheck},
		SessionTranscript:  transcript,
		DocType:            testDocType,
		VerifierInput:      input,
	}
}

// testDocType is the docType the shared challenge vectors use, so a
// request built from the fixture derives a digest those vectors pin.
const testDocType = "eu.europa.ec.eudi.nym_auth.1"

// e2 is DERIVED from the request's own transcript and docType, and the
// value it derives is the one the shared vectors pin. A request that
// carried e2 as a field could name one session in the seed and another
// in the digest; this is what makes that unrepresentable.
func TestRequestDerivesThePinnedChallengeDigest(t *testing.T) {
	r := testRequest(t)
	got, err := r.E2()
	require.NoError(t, err)
	assert.Equal(t,
		"7eea0f8e073961c3e82e9562e0f79edaa66dbfc17eaf0ac0596a987733516dd9",
		hex.EncodeToString(got[:]),
		"challenge-vectors.json, verifier 1")
}

// verifier_input is SHA-256 of the BARE verifier_id, and the rulebook's
// worked digest is what proves it - not our own output.
func TestVerifierInputIsTheBareIDsDigest(t *testing.T) {
	got, err := VerifierInput("verifier.example")
	require.NoError(t, err)
	assert.Equal(t, "be6a6400", hex.EncodeToString(got[:])[:8],
		"nym_auth_rulebook PR #7's MUST digest for the bare verifier_id")

	// The prefixed Client Identifier is the form that rulebook marks
	// MUST NOT, and it is refused rather than stripped: hashing it
	// yields a pseudonym no Verifier reports, so a comparison never
	// matches and the subject looks innocent.
	for _, prefixed := range []string{"x509_san_dns:verifier.example", "semantic_id:verifier.example"} {
		_, err := VerifierInput(prefixed)
		assert.Errorf(t, err, "%q is a Client Identifier, not a verifier_id", prefixed)
	}

	_, err = VerifierInput("")
	assert.Error(t, err)
}

// Every input the circuit is checked against is the verifier's own, so
// a request missing one is refused rather than defaulted - a default
// here would be a value nobody chose, checked as if someone had.
func TestRequestRefusesWhatItCannotCheckAgainst(t *testing.T) {
	require.NoError(t, testRequest(t).Check(), "the fixture itself must be valid")

	t.Run("no issuer key", func(t *testing.T) {
		r := testRequest(t)
		r.IssuerKey = nil
		assert.ErrorContains(t, r.Check(), "never from the proof")
	})

	t.Run("an issuer key on the wrong curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		r := testRequest(t)
		r.IssuerKey = &key.PublicKey
		assert.ErrorContains(t, r.Check(), "P-256")
	})

	t.Run("no verification time", func(t *testing.T) {
		r := testRequest(t)
		r.Now = time.Time{}
		assert.ErrorContains(t, r.Check(), "year 1")
	})

	t.Run("an input that leaves a circuit input unset", func(t *testing.T) {
		r := testRequest(t)
		r.Inputs = []CircuitInput{{FunctionID: FunctionAgeCheck, Values: map[string][]byte{InputEarliest: []byte("2000-01-01")}}}
		assert.ErrorContains(t, r.Check(), "unset")
	})

	t.Run("a function the circuit does not support", func(t *testing.T) {
		r := testRequest(t)
		r.SupportedFunctions = nil
		assert.ErrorContains(t, r.Check(), "does not support")
	})

	t.Run("no transcript seed", func(t *testing.T) {
		r := testRequest(t)
		r.SessionTranscript = nil
		assert.ErrorContains(t, r.Check(), "the transcript seed is 0 bytes")
	})

	t.Run("a transcript seed over the circuits' bound", func(t *testing.T) {
		r := testRequest(t)
		r.SessionTranscript = make([]byte, MaxTranscriptBytes+1)
		assert.ErrorContains(t, r.Check(), "the circuits take 32 to 65536")
	})

	t.Run("a transcript seed that is not one CBOR array", func(t *testing.T) {
		// Trailing bytes: long enough to clear the length bound, so
		// what refuses it is the shape check in the derivation.
		r := testRequest(t)
		r.SessionTranscript = append(append([]byte{}, r.SessionTranscript...), 0x00)
		assert.ErrorContains(t, r.Check(), "not a single CBOR array")
	})

	t.Run("no docType", func(t *testing.T) {
		r := testRequest(t)
		r.DocType = ""
		assert.ErrorContains(t, r.Check(), "binds the proof to this credential type")
	})

	t.Run("zero verifier_input", func(t *testing.T) {
		r := testRequest(t)
		r.VerifierInput = [32]byte{}
		assert.ErrorContains(t, r.Check(), "scoped to this verifier")
	})
}

// T is 20 ASCII bytes in UTC. The layout writes a literal "Z", so a
// non-UTC time would render its own wall clock under a UTC marker - a
// different instant, asserted as this one.
func TestTimeStringIsUTCAndBounded(t *testing.T) {
	r := testRequest(t)

	zone := time.FixedZone("UTC+2", 2*60*60)
	r.Now = time.Date(2026, 10, 7, 14, 0, 0, 0, zone)
	got, err := r.TimeString()
	require.NoError(t, err)
	assert.Equal(t, "2026-10-07T12:00:00Z", got, "the same instant, written in UTC")
	assert.Len(t, got, 20, "the circuits take exactly 20 ASCII bytes")

	r.Now = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = r.TimeString()
	assert.ErrorContains(t, err, "20-byte time format",
		"a year the layout cannot express would silently render as four other digits")
}
