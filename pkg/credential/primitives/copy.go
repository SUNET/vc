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

// Apply implements Applier. It writes the input claim's value, of any type,
// at Output. An absent input claim is a no-op.
func (a *CopyArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	val, present := lookupClaim(claims, a.Input)
	if !present {
		return nil, nil
	}
	result := map[string]any{}
	if err := setClaim(result, a.Output, val); err != nil {
		return nil, err
	}
	return result, nil
}
