package apiv1

import (
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
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

	// Serialised as a browser would (RFC 6454 §6.2), shared with the
	// Interactive Authorization audience derivation so the two cannot
	// drift - both are compared against something a wallet canonicalised
	// itself, as a plain string.
	origin, err := openid4vp.CanonicalOrigin(raw)
	if err != nil {
		return "", fmt.Errorf("verifier.public_url: %w", err)
	}
	return origin, nil
}
