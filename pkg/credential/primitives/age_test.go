package primitives

import (
	"testing"
	"time"
)

func TestAgeOverThresholds(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	thresholds := []int{13, 15, 18, 21, 65}

	tests := []struct {
		name      string
		birthdate string
		want      map[string]bool
		wantErr   bool
	}{
		{"empty_birthdate", "", nil, true},
		{"malformed", "not-a-date", nil, true},
		{"future_birthdate", "2030-01-01", nil, true},
		{
			"adult_all_true_except_65",
			"1996-01-30",
			map[string]bool{
				"age_over_13": true, "age_over_15": true, "age_over_18": true, "age_over_21": true, "age_over_65": false,
				"over_13_this_year": true, "over_15_this_year": true, "over_18_this_year": true, "over_21_this_year": true, "over_65_this_year": false,
			},
			false,
		},
		{
			"elder_all_true",
			"1950-01-01",
			map[string]bool{
				"age_over_13": true, "age_over_15": true, "age_over_18": true, "age_over_21": true, "age_over_65": true,
				"over_13_this_year": true, "over_15_this_year": true, "over_18_this_year": true, "over_21_this_year": true, "over_65_this_year": true,
			},
			false,
		},
		{
			"child_all_false",
			"2020-05-15",
			map[string]bool{
				"age_over_13": false, "age_over_15": false, "age_over_18": false, "age_over_21": false, "age_over_65": false,
				"over_13_this_year": false, "over_15_this_year": false, "over_18_this_year": false, "over_21_this_year": false, "over_65_this_year": false,
			},
			false,
		},
		{
			"boundary_day_before_birthday",
			"2013-09-26",
			map[string]bool{
				"age_over_13": false, "age_over_15": false, "age_over_18": false, "age_over_21": false, "age_over_65": false,
				"over_13_this_year": true, "over_15_this_year": false, "over_18_this_year": false, "over_21_this_year": false, "over_65_this_year": false,
			},
			false,
		},
		{
			"boundary_on_birthday",
			"2013-09-25",
			map[string]bool{
				"age_over_13": true, "age_over_15": false, "age_over_18": false, "age_over_21": false, "age_over_65": false,
				"over_13_this_year": true, "over_15_this_year": false, "over_18_this_year": false, "over_21_this_year": false, "over_65_this_year": false,
			},
			false,
		},
		{
			"leap_year_feb29_past_birthday",
			"2008-02-29",
			map[string]bool{
				"age_over_13": true, "age_over_15": true, "age_over_18": true, "age_over_21": false, "age_over_65": false,
				"over_13_this_year": true, "over_15_this_year": true, "over_18_this_year": true, "over_21_this_year": false, "over_65_this_year": false,
			},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AgeOverThresholds(tc.birthdate, now, thresholds)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (got=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("wrong size: got %d, want %d", len(got), len(tc.want))
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestAgeOverThresholds_ZeroNowFallsBackToTimeNow(t *testing.T) {
	// A birthdate far enough in the past that every listed threshold is true
	// regardless of the exact current time.
	got, err := AgeOverThresholds("1900-01-01", time.Time{}, []int{18, 65})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["age_over_18"] || !got["age_over_65"] || !got["over_18_this_year"] || !got["over_65_this_year"] {
		t.Fatalf("expected all-true for a 1900-01-01 birthdate, got %v", got)
	}
}
