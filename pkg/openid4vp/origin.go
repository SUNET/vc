package openid4vp

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
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
// An IPv6 literal is serialised the way the WHATWG URL Standard - and
// therefore a browser - does, rather than merely lowercased: the same
// address has many valid spellings and only one canonical one. A port is
// normalised as the number it is, for the same reason.
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
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q has no scheme or host, so it yields no origin", rawURL)
	}

	scheme := strings.ToLower(u.Scheme)

	// Hostname() lowercases nothing and strips the brackets an IPv6
	// literal is written with, so both have to be put back by hand.
	host := u.Hostname()
	if strings.Contains(host, ":") {
		// An IPv6 literal, which is not a domain name and must not be put
		// through IDNA - the colons alone would fail it. Lowercasing is
		// not its canonical form either: a browser serialises an address
		// the way RFC 5952 does, so "[2001:0DB8:0:0:0:0:0:1]" comes back
		// as "[2001:db8::1]" and a lowercased spelling matches neither
		// the Origin it reports nor the audience derived from it.
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return "", fmt.Errorf("parsing the IPv6 literal in %q: %w", rawURL, err)
		}
		host = "[" + serialiseIPv6(addr) + "]"
	} else {
		// ToASCII does the case folding too, as part of the UTS #46
		// mapping, so there is no ToLower here to disagree with it.
		host, err = browserHost.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("serialising the host of %q as a browser would: %w", rawURL, err)
		}
	}

	origin := scheme + "://" + host

	// The port is a NUMBER, and u.Port() hands back whatever was typed.
	// A browser parses it and emits the decimal form, so ":0443" is the
	// default port and disappears, and ":008443" comes back as ":8443" -
	// while comparing the raw strings kept both spellings and failed
	// against the origin a browser reports for the same URL.
	if port := u.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", fmt.Errorf("the port in %q is not a port number: %w", rawURL, err)
		}
		normalised := strconv.FormatUint(number, 10)
		if normalised != defaultPortForScheme(scheme) {
			origin += ":" + normalised
		}
	}
	return origin, nil
}

// serialiseIPv6 writes an address the way the WHATWG URL Standard's IPv6
// serializer does, which is what a browser puts in an Origin.
//
// netip.Addr.String() is RFC 5952 and agrees with it everywhere except
// one case: an IPv4-mapped address comes back with a dotted tail,
// "::ffff:192.0.2.1", while the URL Standard has no such case and emits
// eight hexadecimal pieces, "::ffff:c000:201". Using String() therefore
// not only failed to canonicalise the dotted spelling, it CONVERTED the
// browser's own hexadecimal spelling into one the browser never emits -
// so a correctly configured expected_origins stopped matching.
//
// The compression rule is the same one netip applies: the leftmost
// longest run of two or more zero pieces becomes "::".
func serialiseIPv6(addr netip.Addr) string {
	b := addr.As16()
	var pieces [8]uint16
	for i := range pieces {
		pieces[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}

	bestStart, bestLen := -1, 0
	for i := 0; i < 8; {
		if pieces[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && pieces[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	if bestLen < 2 {
		bestStart = -1
	}

	var out strings.Builder
	for i := 0; i < 8; i++ {
		if i == bestStart {
			out.WriteString("::")
			i += bestLen - 1
			continue
		}
		if i > 0 && i != bestStart+bestLen {
			out.WriteByte(':')
		}
		out.WriteString(strconv.FormatUint(uint64(pieces[i]), 16))
	}
	return out.String()
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
