package primitives

import "testing"

func TestSWAMIDHighestAssuranceLevel(t *testing.T) {
	const (
		al1 = "http://www.swamid.se/policy/assurance/al1"
		al2 = "http://www.swamid.se/policy/assurance/al2"
		al3 = "http://www.swamid.se/policy/assurance/al3"
	)

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

		{"string_swamid_al1", al1, al1},
		{"string_swamid_al2", al2, al2},
		{"string_swamid_al3", al3, al3},

		{"slice_string_swamid_al2", []string{al2}, al2},
		{"slice_any_swamid_picks_al2", []any{al1, al2}, al2},
		{"slice_any_wrong_element_types", []any{123, true}, ""},

		{
			"realistic_al2_assertion_ignores_refeds",
			[]string{
				al1, al2,
				"https://refeds.org/assurance",
				"https://refeds.org/assurance/profile/cappuccino",
				"https://refeds.org/assurance/ID/unique",
				"https://refeds.org/assurance/ID/eppn-unique-no-reassign",
				"https://refeds.org/assurance/IAP/low",
				"https://refeds.org/assurance/IAP/medium",
			},
			al2,
		},
		{"whitespace_tolerated", []string{"  " + al2 + "  "}, al2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SWAMIDHighestAssuranceLevel(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
