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

		// An IPv6 literal is the same address however it is written, and
		// a browser emits the one spelling RFC 5952 prescribes. Compared
		// as a plain string, every other spelling is a mismatch.
		{name: "an IPv6 literal written out in full", in: "https://[2001:0db8:0000:0000:0000:0000:0000:0001]", want: "https://[2001:db8::1]"},
		{name: "an IPv6 literal with a run to compress", in: "https://[2001:db8:0:0:0:0:2:1]", want: "https://[2001:db8::2:1]"},
		{name: "uppercase hextets fold", in: "https://[2001:DB8::ABCD]", want: "https://[2001:db8::abcd]"},
		{name: "the loopback", in: "https://[0:0:0:0:0:0:0:1]", want: "https://[::1]"},

		// A dotted-quad IPv4 address is already what a browser emits.
		{name: "a dotted-quad address", in: "https://127.0.0.1:8443", want: "https://127.0.0.1:8443"},

		// A port is a NUMBER, so leading zeroes are not part of it. A URL
		// parser drops them - and then drops the port itself when what is
		// left is the scheme's default.
		{name: "a default port written with a leading zero", in: "https://issuer.example:0443", want: "https://issuer.example"},
		{name: "a non-default port written with a leading zero", in: "https://issuer.example:08443", want: "https://issuer.example:8443"},
		{name: "several leading zeroes", in: "https://issuer.example:000443", want: "https://issuer.example"},
		{name: "http's default port with a leading zero", in: "http://issuer.example:080", want: "http://issuer.example"},

		// An IPv4-MAPPED IPv6 address is where RFC 5952 and the WHATWG
		// URL Standard part company: net/netip writes the dotted-decimal
		// tail, and a browser has no such special case and reports
		// hexadecimal pieces. The dotted form is an origin nothing emits.
		{name: "an IPv4-mapped address stays hexadecimal", in: "https://[::ffff:c000:201]", want: "https://[::ffff:c000:201]"},
		{name: "an IPv4-mapped address written in full", in: "https://[0:0:0:0:0:ffff:c000:201]", want: "https://[::ffff:c000:201]"},
		{name: "an IPv4-mapped address with a port", in: "https://[::ffff:c000:201]:8443", want: "https://[::ffff:c000:201]:8443"},

		// A single zero piece is written out rather than compressed, and
		// only the LONGEST run is compressed, both per the WHATWG
		// serializer.
		{name: "a single zero piece is not compressed", in: "https://[2001:db8:0:1:1:1:1:1]", want: "https://[2001:db8:0:1:1:1:1:1]"},
		{name: "the longest run wins", in: "https://[1:0:0:1:0:0:0:1]", want: "https://[1:0:0:1::1]"},
		{name: "the unspecified address", in: "https://[::]", want: "https://[::]"},
		{name: "a trailing run", in: "https://[2001:db8:1::]", want: "https://[2001:db8:1::]"},
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

		// url.Parse gives these a non-empty Host and an empty Hostname,
		// so a check on Host alone let them through and returned
		// "https://" as an origin.
		{name: "a port with no host", in: "https://:443"},
		{name: "a port with no host and a path", in: "https://:8443/op/par"},

		// A browser parses a host whose last label is a number with its
		// IPv4 parser and reports the dotted-quad form, so any other
		// spelling would be compared against something it never emits.
		{name: "a short-form IPv4 address", in: "https://127.1"},
		{name: "an IPv4 address with an octal octet", in: "https://127.0.0.01"},
		{name: "a hexadecimal IPv4 address", in: "https://0x7f.0.0.1"},
		{name: "a single-number IPv4 address", in: "https://2130706433"},
		{name: "a domain-looking host with a numeric last label", in: "https://example.1"},

		// A zone identifier names an interface on one machine, so it is
		// not something two parties can compare, and no browser emits one.
		{name: "an IPv6 literal with a zone", in: "https://[fe80::1%25eth0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalOrigin(tc.in)
			assert.Error(t, err)
		})
	}
}

// The numeric-host check has to run on the output of the IDNA mapping as
// well as on the input, because the mapping can produce a numeric host.
//
// The switch asks whether the host AS WRITTEN ends in a number, and
// fullwidth digits are not ASCII digits, so a host spelled in them takes
// the domain-name branch - and UTS #46 maps it to ASCII digits. Before
// this, "https://１２７.１" was published as the origin "https://127.1",
// which no browser will ever report, while the ASCII spelling of exactly
// the same host was refused.
func TestCanonicalOriginRechecksNumericHostsAfterMapping(t *testing.T) {
	for _, tc := range []struct{ name, rawURL string }{
		{"fullwidth digits, short form", "https://１２７.１"},
		{"fullwidth digits, hexadecimal", "https://０x７f.１"},
		{"fullwidth digits, a single number", "https://２１３２7３０６２５"},
		{"a fullwidth trailing label after an ASCII one", "https://example.１"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin, err := CanonicalOrigin(tc.rawURL)
			if err == nil {
				t.Fatalf("a host a browser would rewrite must be refused, got origin %q", origin)
			}
		})
	}

	// The ASCII spellings of the same hosts were already refused; this
	// pins that the two now agree, which is the actual defect.
	for _, rawURL := range []string{"https://127.1", "https://0x7f.1", "https://example.1"} {
		if origin, err := CanonicalOrigin(rawURL); err == nil {
			t.Fatalf("%q must be refused, got %q", rawURL, origin)
		}
	}

	// And a host that maps to a CANONICAL dotted quad is still accepted:
	// the refusal is of spellings a browser rewrites, not of addresses.
	for _, tc := range []struct{ rawURL, want string }{
		{"https://１２７.０.０.１", "https://127.0.0.1"},
		{"https://127.0.0.1", "https://127.0.0.1"},
		{"https://127.0.0.1:8443", "https://127.0.0.1:8443"},
	} {
		got, err := CanonicalOrigin(tc.rawURL)
		if err != nil {
			t.Fatalf("CanonicalOrigin(%q): %v", tc.rawURL, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalOrigin(%q) = %q, want %q", tc.rawURL, got, tc.want)
		}
	}

	// A name that merely CONTAINS digits is a name, not an address.
	for _, tc := range []struct{ rawURL, want string }{
		{"https://1issuer.example.com", "https://1issuer.example.com"},
		{"https://１issuer.example.com", "https://1issuer.example.com"},
		{"https://münchen.example", "https://xn--mnchen-3ya.example"},
	} {
		got, err := CanonicalOrigin(tc.rawURL)
		if err != nil {
			t.Fatalf("CanonicalOrigin(%q): %v", tc.rawURL, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalOrigin(%q) = %q, want %q", tc.rawURL, got, tc.want)
		}
	}
}
