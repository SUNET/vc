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

	e2, err := MdocE2("https://verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.NoError(t, err)

	return Request{
		IssuerKey:          &key.PublicKey,
		Now:                time.Now(),
		Inputs:             []CircuitInput{bounds.CircuitInput()},
		SupportedFunctions: []string{FunctionAgeCheck},
		E2:                 e2,
		VerifierInput:      input,
	}
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

	t.Run("zero e2", func(t *testing.T) {
		r := testRequest(t)
		r.E2 = [32]byte{}
		assert.ErrorContains(t, r.Check(), "not bound to this session")
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
