package httphelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The header a browser actually sends accepts application/json through its
// */* range. Asking "is JSON acceptable" therefore answers yes for every
// browser, which is why PrefersJSON compares the two instead - an endpoint
// that serves a page to people and data to integrators cannot hand the page
// away to the first visitor with a default Accept.
func TestPrefersJSON(t *testing.T) {
	for name, tc := range map[string]struct {
		accept string
		want   bool
	}{
		"an integrator asking for data": {"application/json", true},
		"with a charset parameter":      {"application/json; charset=utf-8", true},
		"json ranked above html":        {"text/html;q=0.8, application/json;q=0.9", true},
		"json through application/*":    {"application/*", true},
		"uppercase is still json":       {"APPLICATION/JSON", true},

		"a browser's default header":   {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", false},
		"html and json ranked equally": {"text/html, application/json", false},
		"curl's wildcard":              {"*/*", false},
		"no header at all":             {"", false},
		"whitespace only":              {"   ", false},
		"html only":                    {"text/html", false},
		"html ranked above json":       {"application/json;q=0.5, text/html", false},
		"something else entirely":      {"application/xml", false},

		// A specific range outranks a wildcard whatever q it carries, so a
		// header that accepts everything but refuses HTML prefers JSON.
		"wildcard accepted, html refused": {"*/*, text/html;q=0", true},
		// ... and the same shape the other way round.
		"wildcard accepted, json refused": {"*/*, application/json;q=0", false},

		// An unparsable q is ignored, not the range carrying it (RFC 9110).
		"unparsable q on json": {"application/json;q=high", true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, PrefersJSON(tc.accept))
		})
	}
}

// A qvalue is 0 to 1 (RFC 9110 12.4.2). Anything else is not a weaker or
// stronger preference, it is not a qvalue - ignored, leaving the range at the
// default of 1, exactly as rendering.go's Accept-Language parser treats it.
func TestPrefersJSONIgnoresAQualityOutsideTheGrammar(t *testing.T) {
	for name, accept := range map[string]string{
		"above one":      "application/json;q=2, text/html",
		"negative":       "application/json;q=-1, text/html",
		"infinity":       "application/json;q=Inf, text/html",
		"not a number":   "application/json;q=NaN, text/html",
		"scientific one": "application/json;q=1e1, text/html",
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, PrefersJSON(accept),
				"a malformed q must not outrank a well-formed one and flip the page to JSON")
		})
	}

	// The bound itself is still honoured at its edges.
	assert.True(t, PrefersJSON("application/json;q=1, text/html;q=0.9"))
	assert.False(t, PrefersJSON("application/json;q=0, text/html;q=0.1"))
}
