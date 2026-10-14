package openid4vp

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// browserHost serialises a hostname the way a URL parser in a browser
// does: UTS #46 ToASCII with the flags the WHATWG URL Standard specifies
// for a non-strict parse.
//
// MapForLookup turns on StrictDomainName and ValidateLabels (and with them
// CheckHyphens), which is right for a resolver and wrong here - a browser
// accepts an underscore in a host and accepts labels like
// "r3---sn-apo3qvuoxuxbt-j5pe", and an origin this rejected would be one
// no comparison could ever match. So those three are turned back off
// after it, and the bidi and joiner checks, which a browser does apply,
// are kept.
var browserHost = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
	idna.VerifyDNSLength(false),
)

// CanonicalOrigin serialises rawURL's origin the way a browser does
// (RFC 6454 §6.2): lowercase scheme and host, and no port when it is the
// default for the scheme.
//
// It matters wherever an origin is COMPARED rather than merely displayed,
// and both places that do so compare it as a plain string - a wallet
// checking expected_origins against the Origin the browser reports, and a
// wallet deriving the audience an Interactive Authorization presentation
// is bound to. A public URL may validly be written with an uppercase host
// or an explicit :443, neither of which a browser ever emits, so an
// unnormalised origin fails a comparison it should pass and the deployment
// looks broken while being configured correctly.
//
// An internationalized host is converted to its A-label form, which is the
// other half of the same problem: a browser reporting an Origin for
// "münchen.example" emits "xn--mnchen-3ya.example", and public_url
// validation accepts the Unicode spelling - so lowercasing alone produced
// an origin nothing would ever match. A host that cannot be converted is
// an error rather than a passthrough: an origin that could not be
// canonicalised must not then be compared as if it had been.
func CanonicalOrigin(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing %q for its origin: %w", rawURL, err)
	}
	// Host rather than Hostname for the first half: a URL such as
	// "https://:443" parses with a non-empty Host and an empty Hostname,
	// and an origin of "https://" is not something this may return.
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q has no scheme or host, so it yields no origin", rawURL)
	}

	scheme := strings.ToLower(u.Scheme)

	// Hostname() lowercases nothing and strips the brackets an IPv6
	// literal is written with, so both have to be put back by hand.
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%q has no host, so it yields no origin", rawURL)
	}

	switch {
	case strings.Contains(host, ":"):
		// An IPv6 literal, which is not a domain name and must not be put
		// through IDNA - the colons alone would fail it.
		//
		// Lowercasing is not enough either: "2001:0DB8:0:0:0:0:0:1" and
		// "2001:db8::1" are the same address written two ways, and a
		// string comparison against the one a browser emits only works
		// if both sides are in the canonical form RFC 5952 describes.
		// netip.Addr.String() produces exactly that.
		host, err = canonicalIPv6(host)
		if err != nil {
			return "", fmt.Errorf("serialising the host of %q as a browser would: %w", rawURL, err)
		}
	case endsInANumber(host):
		// A host whose last label is a number is an IPv4 address to a
		// browser, not a domain name, and it applies its own parser:
		// "127.1" and "0x7f.1" both become "127.0.0.1". IDNA would leave
		// either spelling untouched, so the origin published here would
		// be one no browser ever reports.
		//
		// Refused rather than canonicalised. The spellings a browser
		// accepts are a long tail of octal, hexadecimal and short forms,
		// and a canonicaliser that got one of them wrong would quietly
		// produce a WRONG origin - which is worse than none, because an
		// origin is only ever used to decide that two things match. An
		// operator who wrote a numeric host meant an address, and the
		// dotted-quad spelling of it is unambiguous.
		if _, err := canonicalIPv4(host); err != nil {
			return "", fmt.Errorf("the host of %q is a numeric address a browser would rewrite: %w", rawURL, err)
		}
	default:
		// ToASCII does the case folding too, as part of the UTS #46
		// mapping, so there is no ToLower here to disagree with it.
		host, err = browserHost.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("serialising the host of %q as a browser would: %w", rawURL, err)
		}
	}

	origin := scheme + "://" + host
	if port := u.Port(); port != "" && port != defaultPortForScheme(scheme) {
		origin += ":" + port
	}
	return origin, nil
}

// defaultPortForScheme returns the port a browser leaves out of an origin,
// or "" for a scheme with no default - where every port is significant.
func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	default:
		return ""
	}
}

// canonicalIPv6 returns addr in the single spelling RFC 5952 §4 prescribes,
// which is the one a browser puts in an Origin header.
//
// A zone identifier is refused: it names an interface on one host, so it
// cannot be part of an origin two parties compare, and no browser emits one.
func canonicalIPv6(host string) (string, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("%q is not an IPv6 address: %w", host, err)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("%q carries a zone identifier, which is not part of an origin", host)
	}
	if !addr.Is6() || addr.Is4() {
		return "", fmt.Errorf("%q is not an IPv6 address", host)
	}
	return "[" + addr.String() + "]", nil
}

// canonicalIPv4 accepts host only when it is already the dotted-quad
// spelling of the address it names - the one form every URL parser agrees
// on, and the only one that survives a round trip through a browser
// unchanged.
func canonicalIPv4(host string) (string, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("%q is not a dotted-quad IPv4 address; write it as four decimal octets", host)
	}
	if addr.String() != host {
		return "", fmt.Errorf("%q is not the canonical spelling of %s", host, addr)
	}
	return host, nil
}

// endsInANumber reports whether a browser would parse host as an IPv4
// address rather than a domain name.
//
// The WHATWG URL Standard decides that on the LAST label alone: a host
// ending in a label that is a decimal or hexadecimal number goes to the
// IPv4 parser, however many labels precede it and whatever they contain.
// So "127.1" is an address, and so is "example.0x1".
func endsInANumber(host string) bool {
	labels := strings.Split(host, ".")
	// A single trailing dot is a root label, not an empty last label.
	if len(labels) > 1 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	last := labels[len(labels)-1]
	if last == "" {
		return false
	}

	for _, prefix := range []string{"0x", "0X"} {
		if hex, found := strings.CutPrefix(last, prefix); found {
			return isHexDigits(hex)
		}
	}
	return isDigits(last)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHexDigits(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
