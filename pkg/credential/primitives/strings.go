package primitives

import (
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
)

// LowerCase returns strings.ToLower(s).
func LowerCase(s string) string { return strings.ToLower(s) }

// UpperCase returns strings.ToUpper(s).
func UpperCase(s string) string { return strings.ToUpper(s) }

// Trim returns strings.TrimSpace(s).
func Trim(s string) string { return strings.TrimSpace(s) }

// LowercaseArgs configures the lowercase primitive.
// Scalar strings and []string are handled; other types are an error.
type LowercaseArgs struct {
	// Input is the source claim.
	Input claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"email\"]"`

	// Output is the target claim. Defaults to Input (in-place).
	Output claimpath.Pointer `yaml:"output,omitempty" doc_example:"[\"email\"]"`
}

// Apply implements Applier.
func (a *LowercaseArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	return applyStringElementwise(a.Input, a.Output, claims, LowerCase)
}

// UppercaseArgs configures the uppercase primitive.
type UppercaseArgs struct {
	Input  claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"country\"]"`
	Output claimpath.Pointer `yaml:"output,omitempty" doc_example:"[\"country\"]"`
}

// Apply implements Applier.
func (a *UppercaseArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	return applyStringElementwise(a.Input, a.Output, claims, UpperCase)
}

// TrimArgs configures the trim primitive.
type TrimArgs struct {
	Input  claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"name\"]"`
	Output claimpath.Pointer `yaml:"output,omitempty" doc_example:"[\"name\"]"`
}

// Apply implements Applier.
func (a *TrimArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	return applyStringElementwise(a.Input, a.Output, claims, Trim)
}

// applyStringElementwise reads input (a scalar string or a []string or
// []any of strings), applies fn to each element, and writes the result at
// output, which defaults to input. Absent input claims are a no-op.
func applyStringElementwise(input, output claimpath.Pointer, claims Claims, fn func(string) string) ([]Write, error) {
	val, present, err := claims.Input(input)
	if err != nil || !present {
		return nil, err
	}
	transformed, ok := mapStrings(val, fn)
	if !ok {
		return nil, fmt.Errorf("input claim %s must be a string or []string", input)
	}
	return []Write{{Path: inPlace(input, output), Value: transformed}}, nil
}

// mapStrings applies fn to a string, or to each string of a []string or
// []any. It reports false for any other value.
func mapStrings(val any, fn func(string) string) (any, bool) {
	switch v := val.(type) {
	case string:
		return fn(v), true
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = fn(s)
		}
		return out, true
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			if s, ok := e.(string); ok {
				out[i] = fn(s)
			} else {
				out[i] = e
			}
		}
		return out, true
	}
	return nil, false
}

// inPlace is the claim a primitive writes: output, or input when output
// is unset.
func inPlace(input, output claimpath.Pointer) claimpath.Pointer {
	if output.IsZero() {
		return input
	}
	return output
}
