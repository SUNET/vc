package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9449 §4.2 defines htu as the HTTP target URI WITHOUT query and
// fragment, and this repository's own validator refuses either - so a
// proof built from the whole URI fails against an endpoint published
// with a query, which is an ordinary way to write a multi-tenant
// deployment, and the failure looks like the server's fault.
func TestDPoPHTU(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"nothing to strip":      {"https://as.example/challenge", "https://as.example/challenge"},
		"a query":               {"https://as.example/challenge?tenant=a", "https://as.example/challenge"},
		"a fragment":            {"https://as.example/challenge#frag", "https://as.example/challenge"},
		"both":                  {"https://as.example/challenge?tenant=a#frag", "https://as.example/challenge"},
		"an empty query marker": {"https://as.example/challenge?", "https://as.example/challenge"},
		"a port and a path":     {"https://as.example:8443/op/challenge?x=1", "https://as.example:8443/op/challenge"},
		"a bare origin":         {"https://as.example", "https://as.example"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, dpopHTU(tc.in))
		})
	}
}

// And the result is one this stack's own validator accepts, which is the
// assertion that actually matters: the two have to agree.
func TestDPoPHTUSatisfiesThisStacksValidator(t *testing.T) {
	for _, uri := range []string{
		"https://as.example/challenge",
		"https://as.example/challenge?tenant=a",
		"https://as.example/challenge?tenant=a#frag",
		"https://as.example:8443/op/challenge?x=1&y=2",
	} {
		proof := &oauth2.DPoP{
			HTM: "POST",
			HTU: dpopHTU(uri),
		}
		require.NoError(t, proof.ValidateHTU(),
			"the proof built for %q must satisfy the validator this stack ships", uri)
	}
}
