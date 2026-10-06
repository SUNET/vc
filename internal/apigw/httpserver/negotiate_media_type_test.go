package httpserver

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// negotiateMediaType exists because gin's NegotiateFormat strips every
// ";q=..." before comparing and compares case-sensitively. Both halves of
// that matter here: "application/jwt;q=0" must NOT get the JWT, and
// "Application/JWT" must.
func TestNegotiateMediaType(t *testing.T) {
	const jwt = MediaTypeJWT
	const json = gin.MIMEJSON

	for _, tc := range []struct {
		accept string
		want   string
	}{
		{accept: "", want: json},
		{accept: "   ", want: json},
		{accept: "*/*", want: json},
		{accept: "application/json", want: json},
		{accept: "application/jwt", want: jwt},

		// Case-insensitive (RFC 9110 §8.3.1).
		{accept: "Application/JWT", want: jwt},
		{accept: "APPLICATION/JWT", want: jwt},
		{accept: "Application/Json", want: json},

		// q=0 means "not acceptable" (§12.4.2). A type the header does not
		// mention at all is not acceptable either, per §12.5.1: a
		// representation is acceptable only if it matches a range with q>0.
		// So refusing one of the two does not silently select the other.
		{accept: "application/jwt;q=0", want: ""},
		{accept: "application/json;q=0", want: ""},
		{accept: "application/jwt;q=0, application/json;q=0", want: ""},
		{accept: "*/*;q=0", want: ""},
		{accept: "application/jwt;q=0, application/json", want: json},
		{accept: "application/json;q=0, application/jwt", want: jwt},

		// The highest quality wins, not the order listed.
		{accept: "application/json;q=0.5, application/jwt;q=0.9", want: jwt},
		{accept: "application/jwt;q=0.2, application/json;q=0.8", want: json},

		// A tie goes to the server's preference, which is the unsigned form.
		{accept: "application/jwt, application/json", want: json},
		{accept: "application/jwt;q=0.7, application/json;q=0.7", want: json},

		// The most specific matching range sets the quality (§12.5.1), so a
		// wildcard at a lower quality does not drag an exact match down.
		{accept: "application/jwt, */*;q=0.1", want: jwt},
		{accept: "application/*;q=0.9, */*;q=0.1", want: json},
		{accept: "application/jwt;q=0, */*", want: json},

		// Neither type is on offer.
		{accept: "text/html", want: ""},
		{accept: "text/html, image/png", want: ""},

		// A browser's header: */* at 0.8 matches json first by server order.
		{accept: "text/html,application/xhtml+xml,*/*;q=0.8", want: json},

		// Malformed entries are skipped rather than taken as a match.
		{accept: "notamediatype, application/jwt", want: jwt},
		{accept: "application/jwt;q=notanumber", want: jwt},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			assert.Equal(t, tc.want, negotiateMediaType(tc.accept, json, jwt))
		})
	}
}
