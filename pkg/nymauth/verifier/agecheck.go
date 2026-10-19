package verifier

import (
	"fmt"
	"time"
)

// The bounds that DISABLE an age check, from nym-auth-circuits SPEC
// section 3. They are sentinel dates rather than absent values, because
// the circuit takes both bounds every time.
const (
	// NoLowerBound disables the earliest-birth-date bound, which is to
	// say it sets no maximum age.
	NoLowerBound = "0000-00-00"
	// NoUpperBound disables the cutoff-birth-date bound, which is to say
	// it sets no minimum age.
	NoUpperBound = "9999-12-31"
)

// MinimumRangeDays is the shortest span the rulebook allows between E
// and C when both are set.
//
// A range narrows what a proof reveals about a birth date to the window
// it answers for. A one-day window answers "were you born on this exact
// day", which is not an age check at all - it is a birth-date oracle the
// Verifier can walk. The rulebook sets the floor at a year.
const MinimumRangeDays = 365

// AgeBounds are the circuits' E and C: the earliest and cutoff birth
// dates a proof is made against, as YYYY-MM-DD.
type AgeBounds struct {
	// Earliest is E. NoLowerBound disables it.
	Earliest string
	// Cutoff is C. NoUpperBound disables it.
	Cutoff string
}

// AgeCheck is the rulebook's age_check parameters, as configured on the
// Verifier. Each bound is a YYYY-MM-DD date or empty for absent.
//
// Exactly the four comparisons the rulebook defines, and no others: a
// request cannot express "between these two dates" except by setting a
// lower and an upper bound, which is what Bounds does.
type AgeCheck struct {
	// GE is "born on or after this date" - an inclusive lower bound.
	GE string
	// GT is "born after this date". One day later than GE.
	GT string
	// LE is "born on or before this date" - an inclusive upper bound.
	LE string
	// LT is "born before this date". One day earlier than LE.
	LT string
}

// Bounds maps an age_check to the circuits' (E, C).
//
// The mapping is from SPEC section 3, and the ±1 day on the exclusive
// forms is the whole of it: the circuit's comparisons are INCLUSIVE, so
// "gt d" has to be expressed as "ge d+1" and "lt d" as "le d-1".
// Passing the exclusive date through unchanged would quietly widen the
// window by a day at each end - which, for a check that decides whether
// someone is old enough, is a wrong answer for everyone born on the
// boundary.
func (a AgeCheck) Bounds() (AgeBounds, error) {
	if a.GE != "" && a.GT != "" {
		return AgeBounds{}, fmt.Errorf("nymauth: age_check sets both ge and gt; they are two spellings of one lower bound")
	}
	if a.LE != "" && a.LT != "" {
		return AgeBounds{}, fmt.Errorf("nymauth: age_check sets both le and lt; they are two spellings of one upper bound")
	}

	bounds := AgeBounds{Earliest: NoLowerBound, Cutoff: NoUpperBound}

	switch {
	case a.GE != "":
		if _, err := parseDate(a.GE, "ge"); err != nil {
			return AgeBounds{}, err
		}
		bounds.Earliest = a.GE
	case a.GT != "":
		shifted, err := shiftDate(a.GT, 1, "gt")
		if err != nil {
			return AgeBounds{}, err
		}
		bounds.Earliest = shifted
	}

	switch {
	case a.LE != "":
		if _, err := parseDate(a.LE, "le"); err != nil {
			return AgeBounds{}, err
		}
		bounds.Cutoff = a.LE
	case a.LT != "":
		shifted, err := shiftDate(a.LT, -1, "lt")
		if err != nil {
			return AgeBounds{}, err
		}
		bounds.Cutoff = shifted
	}

	if err := bounds.checkRange(); err != nil {
		return AgeBounds{}, err
	}
	return bounds, nil
}

// checkRange enforces the rulebook's minimum span between two SET
// bounds.
//
// Only when both are set: one bound alone is an ordinary age check and
// reveals nothing but which side of a date the subject falls on. It is
// the PAIR that narrows a birth date to a window, and a narrow enough
// window is an identifier.
func (b AgeBounds) checkRange() error {
	if b.Earliest == NoLowerBound || b.Cutoff == NoUpperBound {
		return nil
	}
	earliest, err := parseDate(b.Earliest, "the earliest birth date")
	if err != nil {
		return err
	}
	cutoff, err := parseDate(b.Cutoff, "the cutoff birth date")
	if err != nil {
		return err
	}
	if !cutoff.After(earliest) {
		return fmt.Errorf("nymauth: the cutoff birth date %s is not after the earliest %s, so no birth date satisfies the request",
			b.Cutoff, b.Earliest)
	}
	if days := int(cutoff.Sub(earliest).Hours() / 24); days < MinimumRangeDays {
		return fmt.Errorf("nymauth: the age range %s..%s spans %d days; the rulebook requires at least %d, because a narrower window identifies a birth date rather than checking an age",
			b.Earliest, b.Cutoff, days, MinimumRangeDays)
	}
	return nil
}

func parseDate(value, what string) (time.Time, error) {
	parsed, err := time.Parse(time.DateOnly, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("nymauth: %s %q is not a YYYY-MM-DD date: %w", what, value, err)
	}
	return parsed, nil
}

// shiftDate moves a date by whole days, in UTC.
//
// AddDate rather than adding 24 hours: a day is not 24 hours in every
// zone, and a DST transition would move the date by two days or none.
// UTC throughout, so the result cannot depend on where the verifier
// runs.
func shiftDate(value string, days int, what string) (string, error) {
	parsed, err := parseDate(value, what)
	if err != nil {
		return "", err
	}
	return parsed.UTC().AddDate(0, 0, days).Format(time.DateOnly), nil
}
