package openid4vp

import (
	"errors"
	"fmt"
	"time"
)

// ProofTimeLayout is the only spelling of T the circuits take: 20
// ASCII bytes, YYYY-MM-DDThh:mm:ssZ.
//
// Second precision, no fractional seconds, upper-case T and Z, no
// offset. T is a public input, bound byte for byte into the proof, so
// "the same instant written differently" is a different input and a
// proof that cannot verify.
const ProofTimeLayout = "2006-01-02T15:04:05Z"

// ProofTimeBytes is the length of that form.
const ProofTimeBytes = 20

// Recommended tolerances for a prover-supplied proof_time.
//
// RECOMMENDATIONS, not protocol constants: the tolerance is the
// verifier's to set. They are here so a deployment that does not
// choose gets the shared defaults rather than something invented.
const (
	RecommendedSkew   = 60 * time.Second
	RecommendedMaxAge = 600 * time.Second
)

// ParseProofTime reads the exact 20-byte form and nothing else.
//
// time.Parse alone is not enough: it accepts spellings this does not
// (a fractional second, a numeric offset) and would turn a value the
// shared vectors refuse into one this verifier accepts. So the length
// and the literal separators are checked first, and the parse then
// settles whether the date is real - no month 13, no 30 February, no
// hour 24.
func ParseProofTime(text string) (time.Time, error) {
	if len(text) != ProofTimeBytes {
		return time.Time{}, fmt.Errorf("%w: proof_time is %d bytes; the form is %d, %q", ErrProofTimeForm, len(text), ProofTimeBytes, ProofTimeLayout)
	}
	if text[10] != 'T' || text[19] != 'Z' {
		return time.Time{}, fmt.Errorf("%w: proof_time %q is not %q: the separators must be upper-case T and Z", ErrProofTimeForm, text, ProofTimeLayout)
	}
	for _, at := range []int{4, 7} {
		if text[at] != '-' {
			return time.Time{}, fmt.Errorf("%w: proof_time %q is not %q", ErrProofTimeForm, text, ProofTimeLayout)
		}
	}
	for _, at := range []int{13, 16} {
		if text[at] != ':' {
			return time.Time{}, fmt.Errorf("%w: proof_time %q is not %q", ErrProofTimeForm, text, ProofTimeLayout)
		}
	}
	for _, at := range []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if text[at] < '0' || text[at] > '9' {
			return time.Time{}, fmt.Errorf("%w: proof_time %q is not %q: %q is not a digit", ErrProofTimeForm, text, ProofTimeLayout, text[at])
		}
	}
	parsed, err := time.Parse(ProofTimeLayout, text)
	if err != nil {
		// Reached only for a date that is well-formed and unreal.
		return time.Time{}, fmt.Errorf("%w: proof_time %q is not a real UTC instant: %v", ErrProofTimeNotAnInstant, text, err)
	}
	return parsed.UTC(), nil
}

// RenderProofTime is the inverse: the 20-byte form of an epoch
// second, refusing a value the form cannot spell.
//
// Out of range rather than clamped or wrapped: a year 10000 or a
// pre-epoch instant has no 20-byte spelling, and inventing one would
// put a value on the wire that no other implementation reads back.
func RenderProofTime(secs int64) (string, error) {
	if secs < ProofTimeMinSecs || secs > ProofTimeMaxSecs {
		return "", fmt.Errorf("%w: %d is outside %d..%d", ErrProofTimeOutOfRange, secs, ProofTimeMinSecs, ProofTimeMaxSecs)
	}
	return time.Unix(secs, 0).UTC().Format(ProofTimeLayout), nil
}

// The proof_time failures, as distinguishable sentinels.
//
// The RESPONSE path reports every spelling failure as proof_time_form,
// which is what the shared response vectors demand. These finer codes
// are the proof_time helper's own vocabulary, which the proof_time
// vectors pin: a caller that wants to tell "not the 20-byte form" from
// "a form that denotes no real instant" can, and the response
// validator deliberately does not.
var (
	// ErrProofTimeForm is a value that is not the 20-byte spelling.
	ErrProofTimeForm = errors.New("proof_time_form")
	// ErrProofTimeNotAnInstant is the right spelling for a date that
	// does not exist - month 13, 30 February, hour 24, second 60.
	ErrProofTimeNotAnInstant = errors.New("proof_time_not_an_instant")
	// ErrProofTimeOutOfRange is an epoch second outside the range the
	// 20-byte form can spell at all.
	ErrProofTimeOutOfRange = errors.New("proof_time_out_of_range")
	// ErrProofTimeInFuture and ErrProofTimeTooOld are the two sides of
	// the tolerance window.
	ErrProofTimeInFuture = errors.New("proof_time_in_future")
	ErrProofTimeTooOld   = errors.New("proof_time_too_old")
)

// The range the 20-byte form can express: 1970-01-01T00:00:00Z to
// 9999-12-31T23:59:59Z.
const (
	ProofTimeMinSecs int64 = 0
	ProofTimeMaxSecs int64 = 253402300799
)

// CheckProofTimeTolerance accepts now-maxAge <= proofTime <= now+skew,
// both inclusive.
//
// The prover supplies T, so a verifier that accepted any T would
// accept a proof made at any time - including one replayed from long
// ago, against a credential since revoked, or one made with a clock
// set forward. The window is what makes a prover-supplied value safe
// to use, so it REFUSES rather than clamping: clamping would verify
// against a T the prover did not use, which cannot succeed anyway and
// would report the wrong reason when it failed.
//
// The message names the observed deviation and the limit, because the
// operator's next question is always "by how much".
func CheckProofTimeTolerance(proofTime, now time.Time, skew, maxAge time.Duration) error {
	if proofTime.After(now.Add(skew)) {
		return fmt.Errorf("%w: proof_time is %s in the future and the skew limit is %s",
			ErrProofTimeInFuture, proofTime.Sub(now).Round(time.Second), skew)
	}
	if proofTime.Before(now.Add(-maxAge)) {
		return fmt.Errorf("%w: proof_time is %s old and the age limit is %s",
			ErrProofTimeTooOld, now.Sub(proofTime).Round(time.Second), maxAge)
	}
	return nil
}

// RenderProofTimeOrPanic is RenderProofTime for a time.Time already
// known to be in range - this century, in practice. It panics rather
// than returning an error so a caller with a literal instant does not
// have to handle one it cannot hit.
func RenderProofTimeOrPanic(t time.Time) string {
	text, err := RenderProofTime(t.UTC().Unix())
	if err != nil {
		panic("openid4vp: proof_time out of range: " + err.Error())
	}
	return text
}
