// Package primitives holds small, general-purpose claim-derivation helpers
// that credentials can wire in via configuration (see e.g.
// pkg/model/data_sources.go's PresentationScope.Derivations). Each primitive
// is a pure function with a matching Args struct + Apply method used by the
// Derivation dispatcher.
package primitives

import (
	"errors"
	"fmt"
	"time"
)

// AgeOverThresholdsArgs configures the age_over_thresholds primitive.
// Emits two boolean claims per threshold: age_over_N (completed years at
// `now`) and over_N_this_year (reaches N at some point in `now`'s calendar
// year, i.e. year(now) - year(birthdate) >= N).
type AgeOverThresholdsArgs struct {
	// Input is the birthdate claim name (value must be ISO YYYY-MM-DD).
	Input string `yaml:"input" validate:"required" doc_example:"birthdate"`

	// Thresholds are the ages (in years) to expose. Each N produces
	// age_over_N and over_N_this_year (booleans). Every entry must be
	// positive.
	Thresholds []int `yaml:"thresholds" validate:"required,min=1,dive,gt=0" doc_example:"[13, 15, 18, 21, 65]"`
}

// Apply implements Applier.
func (a *AgeOverThresholdsArgs) Apply(claims map[string]any, now time.Time) (map[string]any, error) {
	bd, ok := claims[a.Input].(string)
	if !ok || bd == "" {
		return nil, fmt.Errorf("input claim %q missing or not a string", a.Input)
	}
	booleans, err := AgeOverThresholds(bd, now, a.Thresholds)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(booleans))
	for k, v := range booleans {
		out[k] = v
	}
	return out, nil
}

// AgeOverThresholds parses birthdate (ISO YYYY-MM-DD) and returns a map
// containing, for every threshold N: age_over_N (true if the subject had
// completed N years at `now`) and over_N_this_year (true if the subject
// reaches N at some point in `now`'s calendar year, i.e.
// `now.Year() - birthYear >= N`). A zero `now` falls back to time.Now().
// Returns an error if birthdate is empty, malformed, or in the future.
// Callers pick which thresholds are meaningful for their credential type.
func AgeOverThresholds(birthdate string, now time.Time, thresholds []int) (map[string]bool, error) {
	if birthdate == "" {
		return nil, errors.New("birthdate is empty")
	}
	if now.IsZero() {
		now = time.Now()
	}
	bd, err := time.Parse("2006-01-02", birthdate)
	if err != nil {
		return nil, fmt.Errorf("invalid birthdate %q: %w", birthdate, err)
	}
	if bd.After(now) {
		return nil, fmt.Errorf("birthdate %q is in the future", birthdate)
	}
	age := now.Year() - bd.Year()
	ageThisYear := age
	if now.Month() < bd.Month() || (now.Month() == bd.Month() && now.Day() < bd.Day()) {
		age--
	}
	out := make(map[string]bool, 2*len(thresholds))
	for _, t := range thresholds {
		out[fmt.Sprintf("age_over_%d", t)] = age >= t
		out[fmt.Sprintf("over_%d_this_year", t)] = ageThisYear >= t
	}
	return out, nil
}
