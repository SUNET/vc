package credential

import (
	"reflect"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

func TestFilterAgainstVCTM(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: claimpath.Keys("age_over_13")},
		{Path: claimpath.Keys("age_over_18")},
		{Path: claimpath.Keys("date_of_issuance")},
		{Path: claimpath.Keys("date_of_expiry")},
		{Path: claimpath.Keys("address", "locality")},                             // nested path — only address.locality allowed
		{Path: claimpath.New(claimpath.Key("nationalities"), claimpath.Index(1))}, // one element allowed
	}}
	doc := map[string]any{
		"age_over_13":      true,
		"age_over_18":      true,
		"date_of_issuance": "2026-09-28",
		"date_of_expiry":   "2027-09-28",
		"given_name":       "Alice",
		"family_name":      "Smith",
		"birthdate":        "1996-01-30",
		"address":          map[string]any{"locality": "Stockholm", "street": "Kungsgatan 1"},
		"nationalities":    []any{"SE", "FI"},
	}
	got, err := FilterAgainstVCTM(doc, vctm)
	if err != nil {
		t.Fatal(err)
	}

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
	addr, ok := got["address"].(map[string]any)
	if !ok {
		t.Fatalf("expected address to be a map, got %T", got["address"])
	}
	if _, ok := addr["locality"]; !ok {
		t.Errorf("expected address.locality to survive")
	}
	if _, ok := addr["street"]; ok {
		t.Errorf("expected undeclared sibling address.street to be filtered out")
	}
	if nationalities := got["nationalities"]; !reflect.DeepEqual(nationalities, []any{"FI"}) {
		t.Errorf("expected only the declared nationalities element, got %v", nationalities)
	}
}

func TestFilterAgainstVCTM_NilVCTM(t *testing.T) {
	doc := map[string]any{"anything": 1}
	got, err := FilterAgainstVCTM(doc, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result for nil VCTM, got %v", got)
	}
}

func TestFilterAgainstVCTM_EmptyDoc(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: claimpath.Keys("age_over_13")},
	}}
	got, err := FilterAgainstVCTM(map[string]any{}, vctm)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result for empty doc, got %v", got)
	}
}

func TestFilterAgainstVCTM_WildcardHeadAndUnsetPath(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: claimpath.New(claimpath.All())}, // wildcard head: skipped
		{Path: claimpath.Keys("kept")},
	}}
	doc := map[string]any{"kept": 1, "dropped": 2}
	got, err := FilterAgainstVCTM(doc, vctm)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["kept"]; !ok {
		t.Fatalf("expected 'kept' to survive: %v", got)
	}
	if _, ok := got["dropped"]; ok {
		t.Fatalf("expected 'dropped' to be filtered: %v", got)
	}

	vctm.Claims = append(vctm.Claims, sdjwtvc.Claim{})
	if _, err := FilterAgainstVCTM(doc, vctm); err == nil {
		t.Fatal("expected a VCTM claim without a path to be refused")
	}
}
