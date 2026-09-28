package credential

import "testing"

func TestSWAMIDHighestAssuranceLevel(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, ""},
		{"unsupported_type", 42, ""},
		{"empty_slice", []string{}, ""},
		{"unknown_uri", []string{"https://example.com/other"}, ""},
		{"refeds_iap_ignored", []string{"https://refeds.org/assurance/IAP/high"}, ""},

		{"string_swamid_al1", "http://www.swamid.se/policy/assurance/al1", "AL1"},
		{"string_swamid_al2", "http://www.swamid.se/policy/assurance/al2", "AL2"},
		{"string_swamid_al3", "http://www.swamid.se/policy/assurance/al3", "AL3"},

		{
			"slice_string_swamid_al2",
			[]string{"http://www.swamid.se/policy/assurance/al2"},
			"AL2",
		},
		{
			"slice_any_swamid_al2",
			[]any{
				"http://www.swamid.se/policy/assurance/al1",
				"http://www.swamid.se/policy/assurance/al2",
			},
			"AL2",
		},
		{"slice_any_wrong_element_types", []any{123, true}, ""},

		{
			"realistic_al2_assertion_ignores_refeds",
			[]string{
				"http://www.swamid.se/policy/assurance/al1",
				"http://www.swamid.se/policy/assurance/al2",
				"https://refeds.org/assurance",
				"https://refeds.org/assurance/profile/cappuccino",
				"https://refeds.org/assurance/ID/unique",
				"https://refeds.org/assurance/ID/eppn-unique-no-reassign",
				"https://refeds.org/assurance/IAP/low",
				"https://refeds.org/assurance/IAP/medium",
			},
			"AL2",
		},
		{
			"whitespace_tolerated",
			[]string{"  http://www.swamid.se/policy/assurance/al2  "},
			"AL2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SWAMIDHighestAssuranceLevel(tc.in); got != tc.want {
				t.Fatalf("SWAMIDHighestAssuranceLevel(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
