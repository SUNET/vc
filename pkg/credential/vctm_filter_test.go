package credential

import (
	"testing"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

func strPtr(s string) *string { return &s }

func TestFilterAgainstVCTM(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: []*string{strPtr("age_over_13")}},
		{Path: []*string{strPtr("age_over_18")}},
		{Path: []*string{strPtr("date_of_issuance")}},
		{Path: []*string{strPtr("date_of_expiry")}},
		{Path: []*string{strPtr("address"), strPtr("locality")}}, // nested path — top-level "address" is allowed
	}}
	doc := map[string]any{
		"age_over_13":      true,
		"age_over_18":      true,
		"date_of_issuance": "2026-09-28",
		"date_of_expiry":   "2027-09-28",
		"given_name":       "Alice",
		"family_name":      "Smith",
		"birthdate":        "1996-01-30",
		"address":          map[string]any{"locality": "Stockholm"},
	}
	got := FilterAgainstVCTM(doc, vctm)

	for _, k := range []string{"age_over_13", "age_over_18", "date_of_issuance", "date_of_expiry", "address"} {
		if _, ok := got[k]; !ok {
			t.Errorf("expected key %q to survive filter", k)
		}
	}
	for _, k := range []string{"given_name", "family_name", "birthdate"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected key %q to be filtered out", k)
		}
	}
}

func TestFilterAgainstVCTM_NilVCTM(t *testing.T) {
	doc := map[string]any{"anything": 1}
	got := FilterAgainstVCTM(doc, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty result for nil VCTM, got %v", got)
	}
}

func TestFilterAgainstVCTM_EmptyDoc(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: []*string{strPtr("age_over_13")}},
	}}
	got := FilterAgainstVCTM(map[string]any{}, vctm)
	if len(got) != 0 {
		t.Fatalf("expected empty result for empty doc, got %v", got)
	}
}

func TestFilterAgainstVCTM_SkipsEmptyOrWildcardPath(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: nil},                        // defensive: skipped
		{Path: []*string{nil}},             // wildcard head: skipped
		{Path: []*string{strPtr("kept")}},
	}}
	doc := map[string]any{"kept": 1, "dropped": 2}
	got := FilterAgainstVCTM(doc, vctm)
	if _, ok := got["kept"]; !ok {
		t.Fatalf("expected 'kept' to survive: %v", got)
	}
	if _, ok := got["dropped"]; ok {
		t.Fatalf("expected 'dropped' to be filtered: %v", got)
	}
}
