package httphelpers

import (
	"strconv"
	"strings"
)

// PrefersJSON reports whether an Accept header ranks application/json
// strictly above text/html.
//
// gin's NegotiateFormat decides a different question. It returns the first
// offered type the header finds acceptable, and a browser's
// "text/html,...,*/*;q=0.8" accepts application/json through the */* range -
// so offering JSON first hands JSON to every browser. An endpoint that
// serves a page to people and data to integrators has to compare the two,
// not ask whether JSON is acceptable at all.
//
// Strictly above, so that everything which expresses no preference - no
// header, "*/*" from curl, a browser listing both - keeps the page it has
// always been served. Asking for data is deliberate: send
// "Accept: application/json".
func PrefersJSON(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return false
	}
	return acceptQuality(accept, "application", "json") > acceptQuality(accept, "text", "html")
}

// Media-range specificity: "type/subtype" outranks "type/*", which outranks
// "*/*", whatever q each carries.
const (
	specificityNone = iota
	specificityAny
	specificityType
	specificityExact
)

// acceptQuality returns the q value an Accept header gives one media type,
// taken from the most specific range that matches it. 0 means the header
// does not accept it.
func acceptQuality(accept, mediaType, subType string) float64 {
	bestQuality, bestSpecificity := 0.0, specificityNone

	for _, entry := range strings.Split(accept, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ";")

		specificity := specificityNone
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case mediaType + "/" + subType:
			specificity = specificityExact
		case mediaType + "/*":
			specificity = specificityType
		case "*/*":
			specificity = specificityAny
		default:
			continue
		}
		if specificity < bestSpecificity {
			continue
		}

		quality := 1.0
		for _, param := range parts[1:] {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			// RFC 9110 says to ignore a parameter that will not parse,
			// not the range carrying it.
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				quality = parsed
			}
		}

		// A more specific range wins even when its q is lower, which is how
		// "*/*;q=1, text/html;q=0" refuses HTML while accepting the rest.
		if specificity > bestSpecificity || quality > bestQuality {
			bestQuality, bestSpecificity = quality, specificity
		}
	}

	return bestQuality
}
