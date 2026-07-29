package httphelpers

import (
	"testing"
)

// FuzzParseAdvancedSExp fuzzes the SPOCP S-expression parser.
// This is a recursive descent parser processing authorization rules —
// a classic fuzz target for uncovering panics from malformed input.
func FuzzParseAdvancedSExp(f *testing.F) {
	// Valid forms
	f.Add("(vc (method POST)(path /api/v1/upload)(subject alice))")
	f.Add("(*)")
	f.Add("(* prefix /api/v1/)")
	f.Add("(* suffix .pdf)")
	f.Add("(* set read write delete)")
	f.Add("(method *)")
	f.Add("(path /api/v1/*)")

	// Edge cases
	f.Add("")
	f.Add("(")
	f.Add(")")
	f.Add("((()))")
	f.Add("(* unknown form)")
	f.Add("(* set)")
	f.Add("(tag")                    // unclosed
	f.Add(string(make([]byte, 512))) // large input

	f.Fuzz(func(t *testing.T, input string) {
		elem, err := parseAdvancedSExp(input)
		if err != nil {
			return // most random inputs are invalid — that's fine
		}
		// If parsing succeeded, the result must be non-nil
		if elem == nil {
			t.Fatal("parseAdvancedSExp returned nil element without error")
		}
	})
}
