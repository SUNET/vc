package primitives

import (
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
)

// CopyArgs configures the copy primitive.
type CopyArgs struct {
	// Input is the source claim.
	Input claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"birthdate\"]"`
	// Output is the target claim.
	Output claimpath.Pointer `yaml:"output" validate:"required" doc_example:"[\"birth_date\"]"`
}

// Apply implements Applier. It writes the input claim's value, of any type,
// at Output. An absent input claim is a no-op.
func (a *CopyArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	val, present, err := claims.Input(a.Input)
	if err != nil || !present {
		return nil, err
	}
	return []Write{{Path: a.Output, Value: val}}, nil
}
