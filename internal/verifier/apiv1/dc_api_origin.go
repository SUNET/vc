package apiv1

import (
	"fmt"
	"net/url"
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

	return parsed.Scheme + "://" + parsed.Host, nil
}
