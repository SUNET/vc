package openid4vp

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// nowFunc is the clock used by validation logic. Override in tests to avoid flakiness.
var nowFunc = func() time.Time { return time.Now().UTC() }

// ClaimValidation defines a validation rule to apply against extracted credential claims.
type ClaimValidation struct {
	// Rule is the validation rule to apply, e.g., "age_over".
	Rule string `json:"rule" yaml:"rule" validate:"required,oneof=age_over" doc_example:"\"age_over\""`

	// Path is the claim path to validate, e.g., ["birthdate"].
	Path []string `json:"path" yaml:"path" validate:"required,min=1,dive,required" doc_example:"[\"birthdate\"]"`

	// Value is the threshold or expected value for the validation.
	Value any `json:"value" yaml:"value" validate:"required" doc_example:"18"`
}

// ValidateClaims applies validation rules against a set of extracted claims.
// claims is a map of claim names to their values (from selective disclosures or JWT payload).
func ValidateClaims(claims map[string]any, validations []ClaimValidation) error {
	for _, v := range validations {
		switch v.Rule {
		case "age_over":
			if err := validateAgeOver(claims, v.Path, v.Value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown validation rule: %s", v.Rule)
		}
	}
	return nil
}

// validateAgeOver checks that a date claim (e.g., birthdate) indicates age >= threshold.
// The date must be in RFC 3339 full-date format (YYYY-MM-DD) per SD-JWT VC / PID spec.
func validateAgeOver(claims map[string]any, path []string, threshold any) error {
	if len(path) == 0 {
		return fmt.Errorf("age_over validation: empty path")
	}

	thresholdAge, ok := toInt(threshold)
	if !ok {
		return fmt.Errorf("age_over validation: threshold must be an integer, got %T", threshold)
	}
	if thresholdAge < 0 {
		return fmt.Errorf("age_over validation: threshold must be non-negative, got %d", thresholdAge)
	}

	// Resolve the claim value from the path
	val, ok := resolvePath(claims, path)
	if !ok {
		return fmt.Errorf("age_over validation: claim %v not found", path)
	}

	dateStr, ok := val.(string)
	if !ok {
		return fmt.Errorf("age_over validation: claim %v is not a string, got %T", path, val)
	}

	birthdate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return fmt.Errorf("age_over validation: invalid date format for %v: %w", path, err)
	}

	now := nowFunc()
	age := computeAge(birthdate, now)

	if age < thresholdAge {
		return fmt.Errorf("age_over validation failed: subject does not meet minimum age requirement of %d", thresholdAge)
	}

	return nil
}

// computeAge calculates the age in full years between birthdate and now.
func computeAge(birthdate, now time.Time) int {
	years := now.Year() - birthdate.Year()
	// Adjust if birthday hasn't occurred yet this year
	if now.Month() < birthdate.Month() || (now.Month() == birthdate.Month() && now.Day() < birthdate.Day()) {
		years--
	}
	return years
}

// resolvePath walks a nested map using the given path segments.
func resolvePath(claims map[string]any, path []string) (any, bool) {
	var current any = claims
	for _, segment := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// toInt converts a numeric value to int (handles Go numeric types, float64 from standard
// JSON decoding, and json.Number from decoders using UseNumber).
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		if i > math.MaxInt || i < math.MinInt {
			return 0, false
		}
		return int(i), true
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		if n > math.MaxInt || n < math.MinInt {
			return 0, false
		}
		return int(n), true
	case float64:
		if n > float64(maxSafeInt) || n < -float64(maxSafeInt) {
			return 0, false
		}
		i := int64(n)
		if float64(i) != n {
			return 0, false
		}
		if i > math.MaxInt || i < math.MinInt {
			return 0, false
		}
		return int(i), true
	case float32:
		if n > float32(maxSafeInt) || n < -float32(maxSafeInt) {
			return 0, false
		}
		i := int64(n)
		if float32(i) != n {
			return 0, false
		}
		if i > math.MaxInt || i < math.MinInt {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

const maxSafeInt = 1 << 53 // max integer exactly representable in float64
