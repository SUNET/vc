package openid4vp

import (
	"fmt"
	"net/url"
	"strings"
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
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
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
