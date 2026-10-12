package apiv1

import (
	"fmt"
	"net/url"
	"strings"
)

// dcAPIOrigin returns the web origin a Digital Credentials API presentation
// is bound to: the scheme, host and port of the verifier's public URL, with
// no path.
//
// Taken from configuration rather than from the request, deliberately. The
// origin is the whole substance of the DC API handover - it is what ties the
// presentation to the page that asked for it - so accepting a caller's word
// for it would let the caller choose what its own presentation is checked
// against, which is the same as not checking.
//
// This assumes the page calling navigator.credentials.get is served from
// verifier.public_url, which is where this flow's page lives. A deployment
// serving it from some other host would produce a transcript the wallet did
// not build, and verification fails - visibly, rather than by accepting
// something unbound.
func (c *Client) dcAPIOrigin() (string, error) {
	raw := c.cfg.Verifier.PublicURL
	if raw == "" {
		return "", fmt.Errorf("verifier.public_url is not set, so the DC API origin cannot be determined")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parsing verifier.public_url %q for the DC API origin: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("verifier.public_url %q has no scheme or host, so it yields no origin", raw)
	}

	return canonicalOrigin(parsed), nil
}

// canonicalOrigin serialises u's origin the way a browser does (RFC 6454
// §6.2).
//
// That matters because the wallet compares expected_origins against the
// Origin the browser reports, with a plain string comparison. Configuration
// permits three spellings a browser never emits - an uppercase scheme, an
// uppercase host, and a port that is the default for the scheme - so
// https://Verifier.Example:443 is a perfectly valid verifier.public_url
// whose unnormalised origin fails a comparison it should pass, and the
// request is refused for a deployment that did nothing wrong.
//
// The same value is used for the mdoc session transcript, so normalising
// here keeps the request and the transcript agreeing by construction rather
// than by both call sites remembering to do it.
func canonicalOrigin(u *url.URL) string {
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
	return origin
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
