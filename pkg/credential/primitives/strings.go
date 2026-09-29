package primitives

import (
	"fmt"
	"strings"
	"time"
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
	// Input is the source claim name.
	Input string `yaml:"input" validate:"required" doc_example:"email"`

	// Output is the target claim name. Defaults to Input (in-place).
	Output string `yaml:"output,omitempty" doc_example:"email"`
}

// Apply implements Applier.
func (a *LowercaseArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	return applyStringElementwise(a.Input, a.Output, claims, LowerCase)
}

// UppercaseArgs configures the uppercase primitive.
type UppercaseArgs struct {
	Input  string `yaml:"input" validate:"required" doc_example:"country"`
	Output string `yaml:"output,omitempty" doc_example:"country"`
}

// Apply implements Applier.
func (a *UppercaseArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	return applyStringElementwise(a.Input, a.Output, claims, UpperCase)
}

// TrimArgs configures the trim primitive.
type TrimArgs struct {
	Input  string `yaml:"input" validate:"required" doc_example:"name"`
	Output string `yaml:"output,omitempty" doc_example:"name"`
}

// Apply implements Applier.
func (a *TrimArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	return applyStringElementwise(a.Input, a.Output, claims, Trim)
}

// applyStringElementwise reads `input` (a scalar string or a []string or
// []any of strings) from claims, applies fn to each element, and returns
// the result keyed by `output` (defaulting to `input`). Absent input
// claims are a no-op.
func applyStringElementwise(input, output string, claims map[string]any, fn func(string) string) (map[string]any, error) {
	if output == "" {
		output = input
	}
	val, present := claims[input]
	if !present {
		return nil, nil
	}
	switch v := val.(type) {
	case string:
		return map[string]any{output: fn(v)}, nil
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = fn(s)
		}
		return map[string]any{output: out}, nil
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			if s, ok := e.(string); ok {
				out[i] = fn(s)
			} else {
				out[i] = e
			}
		}
		return map[string]any{output: out}, nil
	default:
		return nil, fmt.Errorf("input claim %q must be a string or []string", input)
	}
}
