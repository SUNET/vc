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
	// Input is the source claim name. Supports dot-notation claim paths
	// (e.g. "identity.email") so this primitive can target the same nested
	// claims that AttributeMapper materialises.
	Input string `yaml:"input" validate:"required" doc_example:"email"`

	// Output is the target claim name. Defaults to Input (in-place).
	// Supports dot-notation claim paths.
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
// the result keyed by `output` (defaulting to `input`). Both `input` and
// `output` support dot-notation claim paths (e.g. "identity.email") so a
// derivation configured on a mapped nested claim actually targets that
// nested value instead of a stray top-level dotted key. Absent input
// claims are a no-op.
func applyStringElementwise(input, output string, claims map[string]any, fn func(string) string) (map[string]any, error) {
	if output == "" {
		output = input
	}
	val, present := lookupClaim(claims, input)
	if !present {
		return nil, nil
	}
	var transformed any
	switch v := val.(type) {
	case string:
		transformed = fn(v)
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = fn(s)
		}
		transformed = out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			if s, ok := e.(string); ok {
				out[i] = fn(s)
			} else {
				out[i] = e
			}
		}
		transformed = out
	default:
		return nil, fmt.Errorf("input claim %q must be a string or []string", input)
	}
	result := map[string]any{}
	if err := setClaim(result, output, transformed); err != nil {
		return nil, err
	}
	return result, nil
}

// lookupClaim resolves a claim path in `claims`. A literal top-level key
// takes precedence over nested walking so a mapping that stored the claim
// as one flat "a.b" key is still found; otherwise the path is split on "."
// and walked through nested maps.
func lookupClaim(claims map[string]any, path string) (any, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	if !strings.Contains(path, ".") {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any = claims
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, present := m[p]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// setClaim writes a value at a claim path. For non-dotted paths it sets
// the top-level key directly. For dotted paths it creates intermediate
// maps as needed, mirroring credential.SetNestedValue's semantics.
func setClaim(dst map[string]any, path string, value any) error {
	if path == "" {
		return fmt.Errorf("empty output path")
	}
	if !strings.Contains(path, ".") {
		dst[path] = value
		return nil
	}
	parts := strings.Split(path, ".")
	cur := dst
	for i := 0; i < len(parts)-1; i++ {
		next, exists := cur[parts[i]]
		if !exists {
			nm := map[string]any{}
			cur[parts[i]] = nm
			cur = nm
			continue
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("path conflict: %s is not a map", strings.Join(parts[:i+1], "."))
		}
		cur = nm
	}
	cur[parts[len(parts)-1]] = value
	return nil
}
