package primitives

import (
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
)

// swamidAssuranceRank orders recognised SWAMID Assurance Framework URIs;
// higher rank is stronger. The URIs are federation-defined identifiers,
// not endpoints.
var swamidAssuranceRank = map[string]int{
	"http://www.swamid.se/policy/assurance/al1": 1, // NOSONAR — SWAMID identifier, not an endpoint
	"http://www.swamid.se/policy/assurance/al2": 2, // NOSONAR — SWAMID identifier, not an endpoint
	"http://www.swamid.se/policy/assurance/al3": 3, // NOSONAR — SWAMID identifier, not an endpoint
}

// SWAMIDHighestAssuranceLevel reads a SAML eduPersonAssurance claim value
// (single string, []string, or []any of strings) and returns the strongest
// recognised SWAMID Assurance Framework URI. Non-SWAMID URIs (including
// REFEDS IAP) are ignored. Returns "" when the value is missing, of an
// unsupported type, or holds no SWAMID URI.
func SWAMIDHighestAssuranceLevel(value any) string {
	var uris []string
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		uris = []string{v}
	case []string:
		uris = v
	case []any:
		uris = make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				continue
			}
			uris = append(uris, s)
		}
	default:
		return ""
	}

	bestURI := ""
	bestRank := 0
	for _, u := range uris {
		u = strings.TrimSpace(u)
		r, ok := swamidAssuranceRank[u]
		if !ok {
			continue
		}
		if r > bestRank {
			bestURI = u
			bestRank = r
		}
	}
	return bestURI
}

// SWAMIDHighestAssuranceLevelArgs configures the
// swamid_highest_assurance_level primitive. Reduces a multi-valued
// eduPersonAssurance claim to the strongest recognised SWAMID URI; hard
// errors if the input is present but no SWAMID URI is recognised.
type SWAMIDHighestAssuranceLevelArgs struct {
	// Input is the source claim (string or list of strings).
	Input claimpath.Pointer `yaml:"input" validate:"required" doc_example:"[\"assurance_level\"]"`

	// Output is the target claim. Defaults to Input (in-place).
	Output claimpath.Pointer `yaml:"output,omitempty" doc_example:"[\"assurance_level\"]"`
}

// Apply implements Applier.
func (a *SWAMIDHighestAssuranceLevelArgs) Apply(claims Claims, _ time.Time) ([]Write, error) {
	val, present, err := claims.Input(a.Input)
	if err != nil || !present {
		return nil, err
	}
	uri := SWAMIDHighestAssuranceLevel(val)
	if uri == "" {
		return nil, fmt.Errorf("no recognized SWAMID assurance URI in claim %s", a.Input)
	}
	return []Write{{Path: inPlace(a.Input, a.Output), Value: uri}}, nil
}
