// Package credential — SWAMID assurance-level mapping.
//
// The transform "swamid_highest_assurance_level" (see transformer.go)
// canonicalises a SAML eduPersonAssurance attribute to one of "AL1", "AL2",
// or "AL3" by picking the strongest recognised URI. This file holds the
// SWAMID Assurance Framework URI catalog and the reducer used by that
// transform.
//
// Scope is deliberately SWAMID only. REFEDS IAP and other federation
// profiles are ignored even when present in the same attribute. When a
// second federation needs its own mapping, add a sibling file and a
// matching transform key rather than growing this catalog.
package credential

import "strings"

const (
	assuranceLevel1 = "AL1"
	assuranceLevel2 = "AL2"
	assuranceLevel3 = "AL3"
)

// swamidAssuranceURIs maps recognised SWAMID Assurance Framework URIs to a
// canonical AL string.
var swamidAssuranceURIs = map[string]string{
	"http://www.swamid.se/policy/assurance/al1": assuranceLevel1,
	"http://www.swamid.se/policy/assurance/al2": assuranceLevel2,
	"http://www.swamid.se/policy/assurance/al3": assuranceLevel3,
}

// swamidAssuranceRank orders AL strings; higher is stronger.
var swamidAssuranceRank = map[string]int{
	assuranceLevel1: 1,
	assuranceLevel2: 2,
	assuranceLevel3: 3,
}

// SWAMIDHighestAssuranceLevel reads a SAML eduPersonAssurance claim value
// (single string, []string, or []any of strings) and returns the strongest
// recognised SWAMID Assurance Framework AL string ("AL1", "AL2", or "AL3").
// Non-SWAMID URIs (including REFEDS IAP) are ignored. Returns "" when the
// value is missing, of an unsupported type, or holds no SWAMID URI.
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

	best := ""
	for _, u := range uris {
		lvl, ok := swamidAssuranceURIs[strings.TrimSpace(u)]
		if !ok {
			continue
		}
		if best == "" || swamidAssuranceRank[lvl] > swamidAssuranceRank[best] {
			best = lvl
		}
	}
	return best
}
