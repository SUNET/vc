package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The circuits compare INCLUSIVELY, so the rulebook's exclusive forms
// have to be shifted by a day. Passing them through unchanged widens the
// window by a day at each end - a wrong answer for everyone born on the
// boundary, which is exactly the population an age check is about.
func TestAgeCheckMapsToInclusiveBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check AgeCheck
		want  AgeBounds
	}{
		{
			name:  "ge passes through",
			check: AgeCheck{GE: "2008-10-07"},
			want:  AgeBounds{Earliest: "2008-10-07", Cutoff: NoUpperBound},
		},
		{
			name:  "gt is one day later",
			check: AgeCheck{GT: "2008-10-07"},
			want:  AgeBounds{Earliest: "2008-10-08", Cutoff: NoUpperBound},
		},
		{
			name:  "le passes through",
			check: AgeCheck{LE: "2008-10-07"},
			want:  AgeBounds{Earliest: NoLowerBound, Cutoff: "2008-10-07"},
		},
		{
			name:  "lt is one day earlier",
			check: AgeCheck{LT: "2008-10-07"},
			want:  AgeBounds{Earliest: NoLowerBound, Cutoff: "2008-10-06"},
		},
		{
			name:  "absent bounds disable both ends",
			check: AgeCheck{},
			want:  AgeBounds{Earliest: NoLowerBound, Cutoff: NoUpperBound},
		},
		{
			name:  "both ends, far enough apart",
			check: AgeCheck{GE: "2000-01-01", LE: "2008-10-07"},
			want:  AgeBounds{Earliest: "2000-01-01", Cutoff: "2008-10-07"},
		},
		{
			// The shift must cross a month boundary correctly, which a
			// naive day-of-month increment would not.
			name:  "gt at the end of a month",
			check: AgeCheck{GT: "2008-01-31"},
			want:  AgeBounds{Earliest: "2008-02-01", Cutoff: NoUpperBound},
		},
		{
			// And a leap day, which is the case a 24-hour arithmetic
			// would also get wrong.
			name:  "lt just after a leap day",
			check: AgeCheck{LT: "2008-03-01"},
			want:  AgeBounds{Earliest: NoLowerBound, Cutoff: "2008-02-29"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.check.Bounds()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A narrow window is a birth-date oracle rather than an age check: the
// Verifier can walk it. The rulebook floors the span at a year, and the
// floor applies only when BOTH bounds are set - one alone reveals
// nothing but which side of a date the subject falls on.
func TestAgeCheckRefusesANarrowRange(t *testing.T) {
	_, err := AgeCheck{GE: "2008-01-01", LE: "2008-01-02"}.Bounds()
	require.Error(t, err, "a two-day window identifies a birth date")
	assert.Contains(t, err.Error(), "at least 365")

	// One day short, to pin the boundary rather than the order of
	// magnitude.
	_, err = AgeCheck{GE: "2001-01-01", LE: "2001-12-31"}.Bounds()
	require.Error(t, err, "364 days is still short")

	// And exactly the floor passes.
	_, err = AgeCheck{GE: "2001-01-01", LE: "2002-01-01"}.Bounds()
	require.NoError(t, err, "365 days is the documented minimum, so it must be allowed")

	// A single bound is never a range, however it is written.
	for _, check := range []AgeCheck{{GE: "2008-01-01"}, {LE: "2008-01-01"}, {GT: "2008-01-01"}, {LT: "2008-01-01"}} {
		_, err := check.Bounds()
		assert.NoErrorf(t, err, "%+v is one bound, not a window", check)
	}
}

// An empty or reversed window has no satisfying birth date at all, which
// is a configuration mistake rather than a request.
func TestAgeCheckRefusesAnImpossibleRange(t *testing.T) {
	_, err := AgeCheck{GE: "2008-10-07", LE: "2000-01-01"}.Bounds()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no birth date satisfies")

	_, err = AgeCheck{GE: "2008-10-07", LE: "2008-10-07"}.Bounds()
	require.Error(t, err, "a single-day window is not a range")
}

// Two spellings of one bound is a configuration that cannot be honoured
// both ways, so it is refused rather than resolved by precedence.
func TestAgeCheckRefusesTwoSpellingsOfOneBound(t *testing.T) {
	_, err := AgeCheck{GE: "2000-01-01", GT: "2000-01-01"}.Bounds()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lower bound")

	_, err = AgeCheck{LE: "2008-01-01", LT: "2008-01-01"}.Bounds()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upper bound")
}

// A malformed date must not reach the circuit as a sentinel or a zero.
func TestAgeCheckRefusesAMalformedDate(t *testing.T) {
	for _, check := range []AgeCheck{
		{GE: "2008-13-01"}, {GT: "not a date"}, {LE: "2008-02-30"}, {LT: "08-01-01"},
	} {
		_, err := check.Bounds()
		assert.Errorf(t, err, "%+v carries a date no circuit can use", check)
	}
}
