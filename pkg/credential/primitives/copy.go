package primitives

import "time"

// CopyArgs configures the copy primitive.
type CopyArgs struct {
	// Input is the source claim path. Supports dot-notation claim paths and
	// literal dotted keys, such as a namespace-qualified mdoc claim.
	Input string `yaml:"input" validate:"required" doc_example:"birthdate"`
	// Output is the target claim path. Supports dot-notation claim paths.
	Output string `yaml:"output" validate:"required" doc_example:"birth_date"`
}

// Apply implements Applier. It writes a copy of the input claim's value, of
// any type, at Output. An absent input claim is a no-op.
func (a *CopyArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	val, present := lookupClaim(claims, a.Input)
	if !present {
		return nil, nil
	}
	result := map[string]any{}
	if err := setClaim(result, a.Output, cloneClaimValue(val)); err != nil {
		return nil, err
	}
	return result, nil
}

// cloneClaimValue deep-copies the objects and arrays of a claim value, so
// that a write into the copy leaves the source unchanged.
func cloneClaimValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneClaimValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneClaimValue(item)
		}
		return out
	default:
		return v
	}
}
