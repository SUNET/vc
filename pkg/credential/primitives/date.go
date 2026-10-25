package primitives

import (
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
)

// YYYYMMDDToISO converts SCHAC schacDateOfBirth ("YYYYMMDD") to ISO
// full-date ("YYYY-MM-DD"). time.Parse validates day-of-month, so impossible
// dates like "20240230" surface as an error instead of being emitted verbatim.
func YYYYMMDDToISO(s string) (string, error) {
	t, err := time.Parse("20060102", s)
	if err != nil {
		return "", fmt.Errorf("invalid YYYYMMDD date %q: %w", s, err)
	}
	return t.Format("2006-01-02"), nil
}

// YYYYMMDDToISOArgs configures the yyyymmdd_to_iso primitive.
// Impossible calendar dates surface as a hard error.
type YYYYMMDDToISOArgs struct {
	// Input is the source claim (must be a non-empty YYYYMMDD string).
	Input claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"birthdate\"]"`

	// Output is the target claim. Defaults to Input.
	Output claimpath.Pointer `yaml:"output,omitempty" doc_example:"[\"birthdate\"]"`
}

// Apply implements Applier.
func (a *YYYYMMDDToISOArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	val, present, err := claims.Input(a.Input)
	if err != nil || !present {
		return nil, err
	}
	s, ok := val.(string)
	if !ok || s == "" {
		return nil, fmt.Errorf("input claim %s must be a non-empty string", a.Input)
	}
	iso, err := YYYYMMDDToISO(s)
	if err != nil {
		return nil, err
	}
	return []Write{{Path: inPlace(a.Input, a.Output), Value: iso}}, nil
}
