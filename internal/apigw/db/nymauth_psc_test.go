package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The compensating retry's decision, which is the whole correctness of
// finishing an interrupted reset without undoing a subject's recovery.
//
// Tested as a pure predicate rather than only through the store: the
// two cases it has to separate look identical from everything except
// the acceptance, and the wrong answer is silent - a record deleted
// that nobody asked to delete.
func TestCompletesAnInterruptedReset(t *testing.T) {
	const audited = "11111111-1111-1111-1111-111111111111"
	const other = "22222222-2222-2222-2222-222222222222"
	psc := pscDigest("a-commitment")

	t.Run("the audited acceptance is still there, so finish the reset", func(t *testing.T) {
		assert.True(t, completesAnInterruptedReset(audited,
			&NymAuthPSCRecord{PSC: psc, Acceptance: audited}))
	})

	t.Run("a different acceptance of the SAME commitment is a recovery", func(t *testing.T) {
		// The subject came back with the same wallet and the same
		// seed. Matching on the commitment would delete this.
		assert.False(t, completesAnInterruptedReset(audited,
			&NymAuthPSCRecord{PSC: psc, Acceptance: other}))
	})

	t.Run("a different acceptance of a different commitment is a recovery", func(t *testing.T) {
		assert.False(t, completesAnInterruptedReset(audited,
			&NymAuthPSCRecord{PSC: pscDigest("another-commitment"), Acceptance: other}))
	})

	t.Run("no record left, so nothing to finish", func(t *testing.T) {
		assert.False(t, completesAnInterruptedReset(audited, nil))
	})

	t.Run("an audit row from before acceptances were recorded matches nothing", func(t *testing.T) {
		// Fail closed on an empty audited value rather than matching
		// every record with an empty acceptance.
		assert.False(t, completesAnInterruptedReset("",
			&NymAuthPSCRecord{PSC: psc, Acceptance: ""}))
	})
}

// A digest has ONE representation in this store.
//
// hex.DecodeString accepts uppercase and mixed case, and both stores
// persist and compare the string - so the same commitment in different
// casing would conflict with itself, and two casings of one subject
// key would be two records for one person.
func TestHexDigestsMustBeCanonical(t *testing.T) {
	lower := pscDigest("a-commitment")
	upper := strings.ToUpper(lower)
	require.NotEqual(t, lower, upper)

	assert.NoError(t, checkHexDigest(lower, "commitment"))
	assert.ErrorContains(t, checkHexDigest(upper, "commitment"), "not lowercase hex")
	// A mixed-case value built so that it is mixed whatever the digest
	// happened to be: taking the tail of a real digest and upper-casing
	// it does nothing when those characters are all decimal.
	mixed := "A" + lower[1:]
	require.NotEqual(t, lower, mixed)
	assert.ErrorContains(t, checkHexDigest(mixed, "commitment"), "not lowercase hex")

	// The other two refusals keep their own messages, so a caller can
	// tell a casing mistake from a length or encoding one.
	assert.ErrorContains(t, checkHexDigest("zz", "commitment"), "not hex")
	assert.ErrorContains(t, checkHexDigest(lower[:62], "commitment"), "not 32")
}
