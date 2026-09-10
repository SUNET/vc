package openid4vci

import (
	"strings"
	"testing"
)

// TestPARRequestValidatesWithoutPanic is the regression guard for an
// unregistered safe_key.
//
// PARRequest.DynamicParams is tagged safe_key, and this package's own
// NewValidator did not register it, so validating a PARRequest panicked with
// "Undefined validation function 'safe_key'". It panicked with the field
// absent too: validator resolves the tag chain when it first parses the
// struct, so omitempty never got the chance to short-circuit.
func TestPARRequestValidatesWithoutPanic(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  PARRequest
	}{
		{name: "dynamic_params absent", req: PARRequest{}},
		{name: "dynamic_params present", req: PARRequest{DynamicParams: map[string]string{"acr": "loa3"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("validating a PARRequest panicked: %v", r)
				}
			}()
			// The request is otherwise empty, so a validation error is
			// expected and irrelevant; the panic is what this pins.
			_ = CheckSimple(tc.req)
		})
	}
}

// TestSafeKeyRejectsFieldPathInjection pins what the guard accepts, since it
// stands between a caller-supplied map key and a MongoDB field path.
func TestSafeKeyRejectsFieldPathInjection(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{key: "acr", want: true},
		{key: "org_id_2", want: true},
		{key: "A", want: true},
		{key: strings.Repeat("a", 64), want: true},

		{key: "", want: false},
		{key: "identity.given_name", want: false}, // a dot is a field path
		{key: "$set", want: false},                // a Mongo operator
		{key: "a$b", want: false},
		{key: "2fa", want: false}, // must start with a letter
		{key: "_leading", want: false},
		{key: "has space", want: false},
		{key: "has-dash", want: false},
		{key: strings.Repeat("a", 65), want: false},
	} {
		if got := safeKeyRe.MatchString(tc.key); got != tc.want {
			t.Errorf("safe_key(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
