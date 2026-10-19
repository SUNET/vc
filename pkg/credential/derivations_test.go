package credential

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/credential/primitives"
)

func TestApplyDerivations_AgeOverThresholds(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	claims := map[string]any{"birthdate": "1996-01-30"}

	list := []primitives.Derivation{{
		AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
			Input:      "birthdate",
			Thresholds: []int{13, 18, 65},
		},
	}}
	got, err := ApplyDerivations(list, claims, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{"age_over_13": true, "age_over_18": true, "age_over_65": false}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestApplyDerivations_StringPrimitivesElementwise(t *testing.T) {
	claims := map[string]any{
		"email":          "USER@example.com",
		"country_scalar": "sweden",
		"countries_list": []string{"Sweden", "Norway"},
		"dob":            "19960130",
	}

	cases := []struct {
		name    string
		list    []primitives.Derivation
		wantKey string
		wantVal any
	}{
		{
			name: "lowercase in place",
			list: []primitives.Derivation{{
				Lowercase: &primitives.LowercaseArgs{Input: "email"},
			}},
			wantKey: "email",
			wantVal: "user@example.com",
		},
		{
			name: "uppercase with output alias",
			list: []primitives.Derivation{{
				Uppercase: &primitives.UppercaseArgs{Input: "country_scalar", Output: "CC_UPPER"},
			}},
			wantKey: "CC_UPPER",
			wantVal: "SWEDEN",
		},
		{
			name: "country_alpha2 elementwise on []string",
			list: []primitives.Derivation{{
				CountryAlpha2: &primitives.CountryAlpha2Args{Input: "countries_list"},
			}},
			wantKey: "countries_list",
			wantVal: []string{"SE", "NO"},
		},
		{
			name: "trim",
			list: []primitives.Derivation{{
				Trim: &primitives.TrimArgs{Input: "email", Output: "email_trimmed"},
			}},
			wantKey: "email_trimmed",
			wantVal: "USER@example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ApplyDerivations(tc.list, claims, time.Time{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if slice, ok := tc.wantVal.([]string); ok {
				gotSlice, ok := got[tc.wantKey].([]string)
				if !ok || len(gotSlice) != len(slice) {
					t.Fatalf("%s: got %v, want %v", tc.wantKey, got[tc.wantKey], tc.wantVal)
				}
				for i := range slice {
					if gotSlice[i] != slice[i] {
						t.Errorf("%s[%d] = %q, want %q", tc.wantKey, i, gotSlice[i], slice[i])
					}
				}
				return
			}
			if got[tc.wantKey] != tc.wantVal {
				t.Errorf("%s = %v, want %v", tc.wantKey, got[tc.wantKey], tc.wantVal)
			}
		})
	}
}

func TestApplyDerivations_YYYYMMDDToISO(t *testing.T) {
	claims := map[string]any{"dob": "19960130"}
	list := []primitives.Derivation{{
		YYYYMMDDToISO: &primitives.YYYYMMDDToISOArgs{Input: "dob", Output: "birthdate"},
	}}
	got, err := ApplyDerivations(list, claims, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["birthdate"] != "1996-01-30" {
		t.Fatalf("got %v, want 1996-01-30", got["birthdate"])
	}
}

func TestApplyDerivations_SWAMIDHighestAssuranceLevel(t *testing.T) {
	claims := map[string]any{
		"raw_assurance": []string{
			"http://www.swamid.se/policy/assurance/al1",
			"http://www.swamid.se/policy/assurance/al2",
			"https://refeds.org/assurance/IAP/medium",
		},
	}
	list := []primitives.Derivation{{
		SWAMIDHighestAssuranceLevel: &primitives.SWAMIDHighestAssuranceLevelArgs{
			Input:  "raw_assurance",
			Output: "assurance_level",
		},
	}}
	got, err := ApplyDerivations(list, claims, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["assurance_level"] != "http://www.swamid.se/policy/assurance/al2" {
		t.Fatalf("got %v", got["assurance_level"])
	}
}

func TestApplyDerivations_Errors(t *testing.T) {
	claims := map[string]any{"birthdate": "1996-01-30"}

	cases := []struct {
		name string
		list []primitives.Derivation
	}{
		{
			name: "missing input claim",
			list: []primitives.Derivation{{
				AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
					Input:      "missing",
					Thresholds: []int{18},
				},
			}},
		},
		{
			name: "empty entry sets no primitive",
			list: []primitives.Derivation{{}},
		},
		{
			name: "more than one primitive set",
			list: []primitives.Derivation{{
				Lowercase: &primitives.LowercaseArgs{Input: "birthdate"},
				Uppercase: &primitives.UppercaseArgs{Input: "birthdate"},
			}},
		},
		{
			name: "yyyymmdd invalid",
			list: []primitives.Derivation{{
				YYYYMMDDToISO: &primitives.YYYYMMDDToISOArgs{Input: "birthdate"},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ApplyDerivations(tc.list, claims, time.Time{}); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestApplyDerivations_MissingInputClaimIsNoOp(t *testing.T) {
	list := []primitives.Derivation{{Lowercase: &primitives.LowercaseArgs{Input: "absent"}}}
	got, err := ApplyDerivations(list, map[string]any{}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

// A pinned claim stays authoritative THROUGH the chain, not just after it.
//
// Each step's output feeds the next, so restoring a value at the end
// leaves everything computed from the overwritten one behind. A step
// converting a stored 19700101 into birth_date, and a later one deriving
// age_over_18 from it, produced an age for the STORED date; putting the
// presented date back afterwards left that age in the credential - an
// assertion the presented date does not support, and one that looks
// perfectly consistent.
func TestPinnedClaimsStayAuthoritativeBetweenDerivationSteps(t *testing.T) {
	list := []primitives.Derivation{
		{YYYYMMDDToISO: &primitives.YYYYMMDDToISOArgs{
			Input: "stored_birth_date", Output: "birth_date",
		}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
			Input: "birth_date", Thresholds: []int{18},
		}},
	}
	claims := map[string]any{
		"stored_birth_date": "19700101",
		"birth_date":        "2010-01-01", // from the verified presentation
	}
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	// Unpinned: age_over_18 is computed from the STORED date.
	unpinned, err := ApplyDerivations(list, claims, now)
	if err != nil {
		t.Fatalf("unpinned: %v", err)
	}
	if unpinned["age_over_18"] != true {
		t.Fatalf("the stored 1970 date should make an adult, got %v", unpinned["age_over_18"])
	}

	// Pinned: the later step reads the presented date instead.
	pinned, err := ApplyDerivationsPinned(list, claims, now, map[string]any{
		"birth_date": "2010-01-01",
	})
	if err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if pinned["age_over_18"] != false {
		t.Fatalf("a 2010 birth date is not over 18 in 2026; got age_over_18=%v", pinned["age_over_18"])
	}

	// The collision is still reported, so the caller can log it.
	if _, ok := pinned["birth_date"]; !ok {
		t.Fatal("a derivation that tried to write the pinned claim must stay visible in the outputs")
	}
}

// An object-valued pin must not be mutated by the steps it survives.
//
// MergeNestedClaims writes INTO existing nested maps, so assigning the pin
// itself into the working claims let a derivation change it: a step
// rewriting a presented address.country changed the pin too, and every
// later step - and the caller's final restoration - then used the derived
// value while believing it was the proved one. Cloning the snapshot once
// is not enough; it has to be cloned on each restoration.
//
// The derivation has to write INTO the pinned object for this to bite,
// which is what a dotted output does; a step that merely runs alongside
// never touches it, and a test using one passes either way.
func TestObjectValuedPinSurvivesTheChain(t *testing.T) {
	list := []primitives.Derivation{
		{Lowercase: &primitives.LowercaseArgs{Input: "address.country"}},
	}
	pin := map[string]any{"address": map[string]any{"country": "DK"}}
	claims := map[string]any{
		"address": map[string]any{"country": "SE", "street_address": "stored"},
	}

	out, err := ApplyDerivationsPinned(list, claims, time.Now(), pin)
	if err != nil {
		t.Fatalf("pinned: %v", err)
	}

	// The derivation ran against the PINNED value, not the stored one.
	derivedAddress, ok := out["address"].(map[string]any)
	if !ok {
		t.Fatalf("expected a nested address output, got %T", out["address"])
	}
	if derivedAddress["country"] != "dk" {
		t.Fatalf("the step should have read the pinned DK, got %v", derivedAddress["country"])
	}

	// And the caller's pin is untouched by it.
	address, ok := pin["address"].(map[string]any)
	if !ok {
		t.Fatal("the pin lost its shape")
	}
	if address["country"] != "DK" {
		t.Fatalf("the pin was mutated: country=%v", address["country"])
	}
}
