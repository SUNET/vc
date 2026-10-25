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
