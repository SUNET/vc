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
func ApplyDerivations(list []primitives.Derivation, claims map[string]any, now time.Time) (map[string]any, error) {
	out := make(map[string]any)
	for i, d := range list {
		derived, err := d.Apply(claims, now)
		if err != nil {
			return nil, fmt.Errorf("derivations[%d]: %w", i, err)
		}
		maps.Copy(out, derived)
	}
	return out, nil
}
