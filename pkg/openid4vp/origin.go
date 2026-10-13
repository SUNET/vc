package openid4vp

import (
	"fmt"
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
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q has no scheme or host, so it yields no origin", rawURL)
	}

	scheme := strings.ToLower(u.Scheme)

	// Hostname() lowercases nothing and strips the brackets an IPv6
	// literal is written with, so both have to be put back by hand.
	host := u.Hostname()
	if strings.Contains(host, ":") {
		// An IPv6 literal, which is not a domain name and must not be put
		// through IDNA - the colons alone would fail it.
		host = "[" + strings.ToLower(host) + "]"
	} else {
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
