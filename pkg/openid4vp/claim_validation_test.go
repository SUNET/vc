package openid4vp

import (
	"testing"
	"time"
)

func TestValidateClaims(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		validations []ClaimValidation
		wantErr     bool
	}{
		{
			name:   "age_over_pass",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-20, 0, 0).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: false,
		},
		{
			name:   "age_over_fail",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-16, 0, 0).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: true,
		},
		{
			name:   "age_over_exactly_18",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-18, 0, 0).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: false,
		},
		{
			name:   "age_over_birthday_tomorrow",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-18, 0, 1).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: true,
		},
		{
			name:   "missing_claim",
			claims: map[string]any{},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: true,
		},
		{
			name:   "invalid_date_format",
			claims: map[string]any{"birthdate": "not-a-date"},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: true,
		},
		{
			name:        "no_validations",
			claims:      map[string]any{"birthdate": "2000-01-01"},
			validations: nil,
			wantErr:     false,
		},
		{
			name:   "unknown_rule",
			claims: map[string]any{"birthdate": "2000-01-01"},
			validations: []ClaimValidation{
				{Rule: "unknown_type", Path: []string{"birthdate"}, Value: 18},
			},
			wantErr: true,
		},
		{
			name:   "float64_threshold",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-20, 0, 0).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: float64(18)},
			},
			wantErr: false,
		},
		{
			name:   "non_integer_float_threshold_rejected",
			claims: map[string]any{"birthdate": time.Now().UTC().AddDate(-20, 0, 0).Format("2006-01-02")},
			validations: []ClaimValidation{
				{Rule: "age_over", Path: []string{"birthdate"}, Value: float64(18.9)},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClaims(tt.claims, tt.validations)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputeAge(t *testing.T) {
	tests := []struct {
		name      string
		birthdate string
		now       string
		expected  int
	}{
		{"simple", "2000-01-01", "2026-06-04", 26},
		{"birthday_today", "2000-06-04", "2026-06-04", 26},
		{"birthday_tomorrow", "2000-06-05", "2026-06-04", 25},
		{"birthday_yesterday", "2000-06-03", "2026-06-04", 26},
		{"leap_year_born", "2000-02-29", "2026-03-01", 26},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bd, _ := time.Parse("2006-01-02", tt.birthdate)
			now, _ := time.Parse("2006-01-02", tt.now)
			age := computeAge(bd, now)
			if age != tt.expected {
				t.Errorf("computeAge(%s, %s) = %d, want %d", tt.birthdate, tt.now, age, tt.expected)
			}
		})
	}
}
