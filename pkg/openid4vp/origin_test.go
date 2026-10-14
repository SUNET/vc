package openid4vp

import (
	"net/netip"
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

		// RFC 5952 is what a browser serialises an address with, and the
		// same address has many valid spellings. Lowercasing alone left
		// the expanded and zero-padded forms unmatchable against the
		// Origin a browser reports for the very same host.
		{name: "a fully expanded IPv6 literal", in: "https://[2001:0db8:0000:0000:0000:0000:0000:0001]", want: "https://[2001:db8::1]"},
		{name: "a zero-padded IPv6 literal", in: "https://[2001:0DB8::0001]:8443", want: "https://[2001:db8::1]:8443"},
		{name: "an IPv6 loopback written the long way", in: "https://[0:0:0:0:0:0:0:1]", want: "https://[::1]"},
		// The WHATWG URL Standard's IPv6 serializer has no IPv4-mapped
		// case: eight hexadecimal pieces, always. Both spellings of the
		// same address therefore come back as the one a browser emits.
		{name: "an IPv4-mapped IPv6 literal written with dots", in: "https://[::ffff:192.0.2.1]", want: "https://[::ffff:c000:201]"},
		{name: "an IPv4-mapped IPv6 literal written in hex", in: "https://[::FFFF:C000:201]", want: "https://[::ffff:c000:201]"},
		{name: "an IPv4-embedded address that is not mapped", in: "https://[64:ff9b::192.0.2.33]", want: "https://[64:ff9b::c000:221]"},

		// A port is a number, not a string. A browser parses it and emits
		// the decimal form, so a leading zero neither survives nor stops
		// a default port from being dropped.
		{name: "a zero-padded default port", in: "https://issuer.example:0443", want: "https://issuer.example"},
		{name: "a zero-padded non-default port", in: "https://issuer.example:008443", want: "https://issuer.example:8443"},
		{name: "a zero-padded default port on http", in: "http://issuer.example:00080/op", want: "http://issuer.example"},
		{name: "port zero is a port", in: "https://issuer.example:0", want: "https://issuer.example:0"},

		// A browser does not treat a dotted host as a name when its last
		// part is numeric: every one of these IS 127.0.0.1, and the
		// Origin a browser reports for them says so.
		{name: "an IPv4 address written in full", in: "http://127.0.0.1", want: "http://127.0.0.1"},
		{name: "a shortened IPv4 address", in: "http://127.1", want: "http://127.0.0.1"},
		{name: "a three-part IPv4 address", in: "http://127.0.1", want: "http://127.0.0.1"},
		{name: "a one-part IPv4 address", in: "http://2130706433", want: "http://127.0.0.1"},
		{name: "an octal IPv4 address", in: "http://0177.0.0.01", want: "http://127.0.0.1"},
		{name: "a hexadecimal IPv4 address", in: "http://0x7f.0x0.0x0.0x1", want: "http://127.0.0.1"},
		{name: "a mixed-radix IPv4 address", in: "http://0x7f.1", want: "http://127.0.0.1"},
		{name: "a zero-padded IPv4 address", in: "http://127.000.000.001", want: "http://127.0.0.1"},
		{name: "an IPv4 address with a trailing dot", in: "http://127.0.0.1.", want: "http://127.0.0.1"},
		{name: "an IPv4 address with a port", in: "http://127.1:8080", want: "http://127.0.0.1:8080"},

		// And a host that merely CONTAINS digits is still a name.
		{name: "a hostname with numeric labels", in: "https://1.example.com", want: "https://1.example.com"},
		{name: "a hostname ending in a non-numeric label", in: "https://127.0.0.1x", want: "https://127.0.0.1x"},

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
		{name: "something bracketed that is not an address", in: "https://[2001:db8::zz]"},
		{name: "a port outside the range a port can take", in: "https://issuer.example:70000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalOrigin(tc.in)
			assert.Error(t, err)
		})
	}
}

// serialiseIPv6 reimplements a serializer net/netip already has, so the
// two are held to each other everywhere they are supposed to agree -
// which is everywhere except the IPv4-mapped case the URL Standard does
// not have. Without this the hand-written compression could drift and
// only the handful of cases spelled out above would notice.
func TestSerialiseIPv6AgreesWithNetipExceptWhereItMustNot(t *testing.T) {
	for _, in := range []string{
		"::", "::1", "2001:db8::1", "2001:db8:0:0:1:0:0:1",
		"fe80::1", "ff02::2", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"64:ff9b::c000:221", "0:1:0:0:0:0:0:8", "1:0:0:2:0:0:0:3",
	} {
		addr, err := netip.ParseAddr(in)
		require.NoError(t, err)
		require.False(t, addr.Is4In6(), "%s is the case the two deliberately differ on", in)
		assert.Equal(t, addr.String(), serialiseIPv6(addr), "disagreed on %s", in)
	}

	// And the one case they must differ on.
	mapped, err := netip.ParseAddr("::ffff:192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, "::ffff:192.0.2.1", mapped.String(), "netip renders the dotted tail")
	assert.Equal(t, "::ffff:c000:201", serialiseIPv6(mapped), "a browser renders eight hex pieces")
}

// The IPv4 parser is the WHATWG URL Standard's §3.3, not net/netip's, and
// the two disagree about which spellings exist at all. These are the
// shapes the standard accepts and the shapes it does not.
func TestWHATWGIPv4(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "127.0.0.1", want: "127.0.0.1", ok: true},
		{in: "127.1", want: "127.0.0.1", ok: true},
		{in: "0x7f000001", want: "127.0.0.1", ok: true},
		{in: "0377.0.0.1", want: "255.0.0.1", ok: true},
		{in: "0", want: "0.0.0.0", ok: true},
		{in: "4294967295", want: "255.255.255.255", ok: true},

		// Out of range: the last part absorbs only the octets left over.
		{in: "4294967296", ok: false},
		{in: "256.1.1.1", ok: false},
		{in: "1.2.3.4.5", ok: false},
		{in: "08", ok: false}, // 8 is not an octal digit
		{in: "0x", want: "0.0.0.0", ok: true},

		// Not an address at all, because the last part is not a number.
		{in: "example.com", ok: false},
		{in: "127.0.0.1x", ok: false},
		{in: "1.example", ok: false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := whatwgIPv4(tc.in)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
