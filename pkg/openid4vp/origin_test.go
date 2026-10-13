package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CanonicalOrigin exists because an origin is COMPARED as a plain string -
// against the Origin header a browser reports, and against a presentation
// audience. Every case here is one where a correctly configured deployment
// writes its public_url one way and a browser emits another.
func TestCanonicalOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "already canonical", in: "https://issuer.example", want: "https://issuer.example"},
		{name: "an uppercase host, which a browser never emits", in: "https://Issuer.EXAMPLE", want: "https://issuer.example"},
		{name: "an uppercase scheme", in: "HTTPS://issuer.example", want: "https://issuer.example"},
		{name: "the default port, which a browser drops", in: "https://issuer.example:443", want: "https://issuer.example"},
		{name: "http's default port", in: "http://issuer.example:80", want: "http://issuer.example"},
		{name: "a non-default port, which it keeps", in: "https://issuer.example:8443", want: "https://issuer.example:8443"},
		{name: "a path, which is not part of an origin", in: "https://issuer.example/op/par?x=1#f", want: "https://issuer.example"},
		{name: "an IPv6 literal keeps its brackets", in: "https://[2001:DB8::1]:8443", want: "https://[2001:db8::1]:8443"},
		{name: "an IPv6 literal on the default port", in: "https://[2001:db8::1]:443", want: "https://[2001:db8::1]"},

		// An internationalized host. A browser's URL parser runs UTS #46
		// ToASCII, so the Origin it reports is the A-label form; a
		// deployment that writes its public_url in Unicode - which
		// validation accepts - would otherwise produce an origin nothing
		// could ever match.
		{name: "a Unicode host becomes its A-label", in: "https://münchen.example", want: "https://xn--mnchen-3ya.example"},
		{name: "mixed case Unicode folds too", in: "https://MÜNCHEN.example", want: "https://xn--mnchen-3ya.example"},
		{name: "an A-label stays as written", in: "https://xn--mnchen-3ya.example", want: "https://xn--mnchen-3ya.example"},
		{name: "non-Latin scripts", in: "https://δοκιμή.example", want: "https://xn--jxalpdlp.example"},
		{name: "a Unicode host with a port", in: "https://münchen.example:8443", want: "https://xn--mnchen-3ya.example:8443"},

		// A browser's URL parser is not a resolver: it does not apply
		// STD3 rules or the hyphen checks, and a host rejected here would
		// be one no comparison could ever match.
		{name: "an underscore, which browsers accept", in: "https://my_host.example", want: "https://my_host.example"},
		{name: "a label browsers see in the wild", in: "https://r3---sn-apo3qvuoxuxbt-j5pe.example", want: "https://r3---sn-apo3qvuoxuxbt-j5pe.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalOrigin(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A host that cannot be serialised is an error, not a passthrough: an
// origin that was not canonicalised must not then be compared as though it
// had been.
func TestCanonicalOriginRefusesWhatItCannotSerialise(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{name: "no scheme", in: "issuer.example"},
		{name: "no host", in: "https:///op/par"},
		{name: "not a URL at all", in: "://"},
		{name: "a punycode label that decodes to nothing valid", in: "https://xn--a.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalOrigin(tc.in)
			assert.Error(t, err)
		})
	}
}
