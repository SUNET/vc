package credential

import (
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/credential/primitives"
)

// ApplyDerivations runs each configured derivation against `claims` and
// returns the accumulated derived claims (empty map when `list` is empty).
// A per-derivation failure short-circuits with a wrapped error naming the
// offending index.
//
// Each derivation's inputs include both the original claims and every claim
// produced by earlier list entries, so a pipeline such as
//
//	yyyymmdd_to_iso(birthdate_raw -> birthdate) followed by
//	age_over_thresholds(birthdate -> age_over_*)
//
// works without a caller having to pre-merge intermediates.
//
// Intermediate accumulation uses a path-aware deep merge rather than
// maps.Copy so a derivation that targets a nested path (e.g.
// identity.email -> {"identity": {"email": "x"}}) does not replace a
// sibling nested claim (identity.name) produced by an earlier step.
func ApplyDerivations(list []primitives.Derivation, claims map[string]any, now time.Time) (map[string]any, error) {
	return ApplyDerivationsPinned(list, claims, now, nil)
}

// ApplyDerivationsPinned is ApplyDerivations with claims that stay
// authoritative THROUGHOUT the chain.
//
// Each step's output feeds the next, so restoring a value only at the end
// is not enough: a step converting a stored 19700101 into birth_date, and
// a later one computing age_over_18 from it, produce an age for the
// stored date. Putting the real birth_date back afterwards leaves that
// age behind - a credential asserting an age the presented date does not
// support, which is worse than the overwrite it was meant to repair,
// because it looks consistent.
//
// Pinned values are restored into the working claims after every step, so
// a dependent derivation reads the value that will actually be issued.
// They are left in the returned outputs, so a caller can still see which
// derivations tried to write them.
func ApplyDerivationsPinned(list []primitives.Derivation, claims map[string]any, now time.Time, pinned map[string]any) (map[string]any, error) {
	out := make(map[string]any)
	working := CloneNestedClaims(claims)
	// CLONED on every restoration, not assigned. MergeNestedClaims writes
	// INTO existing nested maps, so handing the pin itself to working
	// lets the next step mutate it: a derivation changing a presented
	// address.country from DK to SE changes the pin too, and every later
	// step - and the caller's final restoration - then uses the derived
	// value while believing it is the proved one. Cloning the SNAPSHOT
	// once is not enough; it has to be cloned each time it goes back in.
	restore := func() {
		for name, value := range pinned {
			working[name] = cloneValue(value)
		}
	}
	restore()
	for i, d := range list {
		derived, err := d.Apply(working, now)
		if err != nil {
			return nil, fmt.Errorf("derivations[%d]: %w", i, err)
		}
		MergeNestedClaims(out, derived)
		MergeNestedClaims(working, derived)
		restore()
	}
	return out, nil
}

// MergeNestedClaims deep-merges src into dst. When both dst[k] and src[k]
// are map[string]any, their contents are merged recursively; otherwise
// src[k] replaces dst[k]. This preserves sibling nested claims when a
// derivation produces only a subset of a parent map's keys.
func MergeNestedClaims(dst, src map[string]any) {
	for k, v := range src {
		sm, srcIsMap := v.(map[string]any)
		if !srcIsMap {
			dst[k] = v
			continue
		}
		dm, dstIsMap := dst[k].(map[string]any)
		if !dstIsMap {
			dst[k] = v
			continue
		}
		MergeNestedClaims(dm, sm)
	}
}

// cloneValue deep-copies a claim value so nothing handed out shares
// mutable structure with the original. Maps and slices only: everything
// else a claim carries is immutable.
func cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}

// CloneNestedClaims returns a copy of src with nested map[string]any values
// cloned recursively so later in-place merges on the working map do not
// mutate the caller's original claims map.
func CloneNestedClaims(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			out[k] = CloneNestedClaims(m)
			continue
		}
		out[k] = v
	}
	return out
}
