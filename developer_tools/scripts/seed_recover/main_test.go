package main

import (
	"bytes"
	"testing"

	"github.com/SUNET/vc/pkg/nymauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// psc is refused, because this tool cannot compute it.
//
// known-offender-matching-psc opens a HOLDER-held private_seed. All this
// tool has is the issuer's derived seed, so computing it would hash the
// wrong secret, find no match, and report an ordinary mismatch - which
// in a loop over candidate subjects reads as "not this one", for every
// candidate including the right one. A tool whose exit code accuses
// people must not have a mode that quietly exonerates all of them.
func TestPSCIsRefusedRatherThanComputedFromTheWrongSeed(t *testing.T) {
	seedValue := bytes.Repeat([]byte{7}, 16)

	_, err := computePseudonym(nymauth.ConfigKnownOffenderMatchingPSC, seedValue, "verifier.example", "", "")
	require.Error(t, err, "this tool does not hold the holder's private_seed")
	assert.Contains(t, err.Error(), "holder-held")

	// The ssc configuration it CAN reproduce still works, or the
	// refusal above would be indistinguishable from refusing everything.
	got, err := computePseudonym(nymauth.ConfigKnownOffenderMatchingSSC, seedValue, "verifier.example", "", "")
	require.NoError(t, err)
	assert.Len(t, got, 32)
}

// A malformed -expect is an input error, not a mismatch.
//
// A valid-hex value of the wrong length decoded happily and then compared
// unequal to everything, so the documented remapping loop reported
// "match: no" for every candidate - telling the operator that no subject
// matches, when the truth is that the value they passed is not a
// pseudonym at all.
// An explicitly EMPTY -expect must refuse, not fall back to "no
// expectation".
//
// The documented use is a loop over candidate subjects driven by the
// exit code, where 0 means "this is the person behind that pseudonym".
// `-expect "$reported"` with an unset shell variable supplies the flag
// with an empty value; reading the VALUE alone cannot tell that from the
// flag being absent, so the tool printed a pseudonym, compared nothing
// and exited 0 - reporting a match for the first candidate tried, and
// for every candidate after it.
func TestAnEmptyExpectationRefusesRatherThanSkippingTheComparison(t *testing.T) {
	const secret, pc = "/pki/nym_auth_seed.key", "known-offender-matching-ssc"
	subjects := []string{"198001011234"}

	t.Run("given and empty", func(t *testing.T) {
		err := validateInvocation(secret, subjects, true, "", pc)
		require.Error(t, err, "a comparison was asked for; exiting 0 without one accuses whoever is tried first")
		assert.Contains(t, err.Error(), "empty value")
	})

	t.Run("given and whitespace", func(t *testing.T) {
		err := validateInvocation(secret, subjects, true, "  \t ", pc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty value")
	})

	t.Run("omitted, which is the output-only mode and stays", func(t *testing.T) {
		require.NoError(t, validateInvocation(secret, subjects, false, "", pc),
			"printing a pseudonym without comparing it is a legitimate use")
	})

	t.Run("given without a pseudonym configuration", func(t *testing.T) {
		err := validateInvocation(secret, subjects, true, "abc", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "-pseudonym-config")
	})

	t.Run("a real expectation passes", func(t *testing.T) {
		require.NoError(t, validateInvocation(secret, subjects, true, "9f86d081", pc))
	})

	// The required flags still refuse, or the cases above would be
	// passing against a function that refuses everything.
	assert.Error(t, validateInvocation("", subjects, false, "", ""))
	assert.Error(t, validateInvocation(secret, nil, false, "", ""))
}

func TestExpectMustBeAFullLengthDigest(t *testing.T) {
	const valid = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	for _, tc := range []struct{ name, in string }{
		{"too short", "00"},
		{"one byte short", valid[:len(valid)-2]},
		{"too long", valid + "ab"},
		{"whitespace only", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExpectation(tc.in)
			require.Error(t, err, "this cannot match any subject, so it must not be reported as a mismatch")
			assert.Contains(t, err.Error(), "-expect")
		})
	}

	t.Run("not hex at all", func(t *testing.T) {
		_, err := parseExpectation("zz")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not hex")
	})

	t.Run("a real digest, with surrounding whitespace", func(t *testing.T) {
		got, err := parseExpectation("  " + valid + "\n")
		require.NoError(t, err, "an operator pasting a value must not be punished for a newline")
		assert.Len(t, got, 32)
	})
}
