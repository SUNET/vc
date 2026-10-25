package claimpath

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// arthurDent is the credential of the examples in OpenID4VP 1.0 section
// 7.3.
const arthurDent = `{
  "name": "Arthur Dent",
  "address": {
    "street_address": "42 Market Street",
    "locality": "Milliways",
    "postal_code": "12345"
  },
  "degrees": [
    {"type": "Bachelor of Science", "university": "University of Betelgeuse"},
    {"type": "Master of Science", "university": "University of Betelgeuse"}
  ],
  "nationalities": ["British", "Betelgeusian"]
}`

// TestSelect reproduces the examples of OpenID4VP 1.0 section 7.3, and
// each error rule of the processing in section 7.1.
func TestSelect(t *testing.T) {
	var credential map[string]any
	if err := json.Unmarshal([]byte(arthurDent), &credential); err != nil {
		t.Fatal(err)
	}
	address := map[string]any{"street_address": "42 Market Street", "locality": "Milliways", "postal_code": "12345"}

	tests := []struct {
		pointer string
		want    []any
		err     error
	}{
		{`["name"]`, []any{"Arthur Dent"}, nil},
		{`["address"]`, []any{address}, nil},
		{`["address","street_address"]`, []any{"42 Market Street"}, nil},
		{`["degrees",null,"type"]`, []any{"Bachelor of Science", "Master of Science"}, nil},
		{`["nationalities",1]`, []any{"Betelgeusian"}, nil},

		{`["name","first"]`, nil, ErrMismatch},
		{`["address",null]`, nil, ErrMismatch},
		{`["address",0]`, nil, ErrMismatch},
		{`["middle_name"]`, nil, ErrNoClaim},
		{`["nationalities",2]`, nil, ErrNoClaim},
	}
	for _, tt := range tests {
		t.Run(tt.pointer, func(t *testing.T) {
			got, err := mustPointer(t, tt.pointer).Select(credential)
			if !errors.Is(err, tt.err) {
				t.Fatalf("Select() error = %v, want %v", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Select() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustPointer(t *testing.T, text string) Pointer {
	t.Helper()
	var p Pointer
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestShapes covers where each shape locates a claim, and each rule it
// refuses a pointer by.
func TestShapes(t *testing.T) {
	elements := MDocElements(map[string]map[string]bool{
		"org.iso.18013.5.1":       {"birth_date": true, "family_name": true},
		"eu.europa.ec.eudi.pid.1": {"family_name": true},
	})
	tests := []struct {
		name   string
		shape  Shape
		claims map[string]any
		path   Pointer
		want   any
		err    bool
	}{
		{"nested object", Nested(), map[string]any{"identity": map[string]any{"birthdate": "1990"}}, Keys("identity", "birthdate"), "1990", false},
		{"nested refuses a flat dotted key", Nested(), map[string]any{"identity.birthdate": "1990"}, Keys("identity", "birthdate"), nil, false},
		{"presented mdoc element", MDocQualified("org.iso.18013.5.1"), map[string]any{"eu.europa.ec.eudi.pid.1.birth_date": "1990"}, Keys("eu.europa.ec.eudi.pid.1", "birth_date"), "1990", false},
		{"presented mdoc refuses one key", MDocQualified("org.iso.18013.5.1"), map[string]any{"birth_date": "1990"}, Keys("birth_date"), nil, true},
		{"mdoc document element", elements, map[string]any{"birth_date": "1990"}, Keys("org.iso.18013.5.1", "birth_date"), "1990", false},
		{"mdoc document refuses an undeclared namespace", elements, map[string]any{"birth_date": "1990"}, Keys("eu.europa.ec.eudi.pid.1", "birth_date"), nil, true},
		{"mdoc document refuses a declared element as one key", elements, map[string]any{"birth_date": "1990"}, Keys("birth_date"), nil, true},
		{"mdoc document key the MDDL does not declare", elements, map[string]any{"raw": "1990"}, Keys("raw"), "1990", false},
		{"mdoc document refuses three keys", elements, map[string]any{}, Keys("a", "b", "c"), nil, true},
		{"one claim refuses null", Nested(), map[string]any{"a": []any{"x"}}, New(Key("a"), All()), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := tt.shape.Get(tt.claims, tt.path)
			if (err != nil) != tt.err {
				t.Fatalf("Get() error = %v, want error %v", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCheckResolved finds a pending pointer through maps, slices,
// pointers and a field a custom unmarshaler sets, and names where it is.
func TestCheckResolved(t *testing.T) {
	type leaf struct {
		Path Pointer `yaml:"-"`
	}
	type entry struct {
		Leaves []*leaf `yaml:"leaves"`
	}
	type root struct {
		Entries map[string]entry `yaml:"entries"`
	}
	pending, err := Dotted("given_name")
	if err != nil {
		t.Fatal(err)
	}
	cfg := root{Entries: map[string]entry{"pid": {Leaves: []*leaf{{Path: Keys("a")}, {Path: pending}}}}}

	var found *PendingError
	if !errors.As(CheckResolved(cfg), &found) || found.At != "entries.pid.leaves[1].path" {
		t.Fatalf("CheckResolved() = %v, want the pending pointer at entries.pid.leaves[1].path", found)
	}
	cfg.Entries["pid"].Leaves[1].Path = Keys("b")
	if err := CheckResolved(cfg); err != nil {
		t.Fatalf("CheckResolved() = %v on resolved pointers", err)
	}
}
