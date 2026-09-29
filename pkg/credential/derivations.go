package credential

import (
	"fmt"
	"maps"
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
func ApplyDerivations(list []primitives.Derivation, claims map[string]any, now time.Time) (map[string]any, error) {
	out := make(map[string]any)
	working := make(map[string]any, len(claims))
	maps.Copy(working, claims)
	for i, d := range list {
		derived, err := d.Apply(working, now)
		if err != nil {
			return nil, fmt.Errorf("derivations[%d]: %w", i, err)
		}
		maps.Copy(out, derived)
		maps.Copy(working, derived)
	}
	return out, nil
}
