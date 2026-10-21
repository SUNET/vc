package credential

import (
	"errors"
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

// An age derivation reading a claim an earlier derivation generated is a
// misconfigured chain, not the Holder's data, and must not be marked as
// invalid claim input.
func TestApplyDerivations_InvalidInputFromEarlierDerivationIsNotHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "birthdate", Thresholds: []int{18}}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "age_over_18", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{"birthdate": "1996-01-30"}, now)
	if err == nil {
		t.Fatal("expected an error for a chain reading a generated boolean")
	}
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a misconfigured chain must not be reported as invalid holder input: %v", err)
	}
}

// A holder-supplied invalid birthdate stays marked even after an unrelated
// earlier derivation.
func TestApplyDerivations_InvalidHolderInputAfterEarlierDerivationIsHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{Lowercase: &primitives.LowercaseArgs{Input: "email"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "birthdate", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{"email": "A@B.se", "birthdate": "2099-01-01"}, now)
	if !errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a future birthdate from the holder must stay marked, got %v", err)
	}
}

// A holder value normalised by an earlier derivation is still the holder's
// data: a future birthdate reaching age through yyyymmdd_to_iso stays marked.
func TestApplyDerivations_InvalidHolderInputThroughNormalisationIsHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{YYYYMMDDToISO: &primitives.YYYYMMDDToISOArgs{Input: "birthdate_raw", Output: "birthdate"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "birthdate", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{"birthdate_raw": "20990101"}, now)
	if !errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a future birthdate normalised from the holder's raw value must stay marked, got %v", err)
	}
}

// Reformatting a generated value does not make it holder data.
func TestApplyDerivations_ReformattedGeneratedInputIsNotHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "token", Format: "uuid"}},
		{Trim: &primitives.TrimArgs{Input: "token", Output: "birthdate"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "birthdate", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{}, now)
	if err == nil {
		t.Fatal("expected an error for a chain feeding a uuid into age")
	}
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a generated value must not be reported as invalid holder input: %v", err)
	}
}

// A container created by a computing derivation is generated too, so a
// later derivation reading the container is a configuration fault.
func TestApplyDerivations_GeneratedNestedContainerIsNotHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "identity.birthdate"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "identity", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{}, now)
	if err == nil {
		t.Fatal("expected an error for a chain feeding a generated map into age")
	}
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a generated container must not be reported as invalid holder input: %v", err)
	}
}

// A holder container that a derivation adds a leaf to stays the holder's.
func TestApplyDerivations_HolderContainerKeepsProvenance(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "identity.document_id"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "identity", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{"identity": map[string]any{"name": "x"}}, now)
	if !errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a holder-supplied container must stay marked, got %v", err)
	}
}

// A reformatting primitive that creates a container the holder never
// supplied makes that container generated, so reading it is a
// configuration fault even though its leaf is holder data.
func TestApplyDerivations_ContainerCreatedByReformatIsNotHolderFault(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	list := []primitives.Derivation{
		{Trim: &primitives.TrimArgs{Input: "birthdate_raw", Output: "identity.birthdate"}},
		{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{Input: "identity", Thresholds: []int{18}}},
	}

	_, err := ApplyDerivations(list, map[string]any{"birthdate_raw": "1990-01-01"}, now)
	if err == nil {
		t.Fatal("expected an error for a chain feeding a map into age")
	}
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		t.Errorf("a container no holder supplied must not be reported as invalid holder input: %v", err)
	}
}
