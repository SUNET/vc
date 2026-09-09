package apiv1

import "github.com/SUNET/vc/pkg/openid4vp"

// dcAPIVariant returns base with the response mode the browser's Digital
// Credentials API requires, and nothing else changed.
//
// The two requests a session serves - one behind request_uri for the QR code
// and the same-device link, one for navigator.credentials.get - must be the
// same request seen through different channels. Everything a wallet checks
// (client_id, nonce, response_uri, client_metadata, the DCQL query) has to
// agree, or the two channels ask for different things and only one of them
// is the request the user consented to.
//
// A copy of the whole struct, rather than a second literal, so a field added
// to RequestObject cannot be set on one channel and forgotten on the other.
func dcAPIVariant(base *openid4vp.RequestObject) *openid4vp.RequestObject {
	if base == nil {
		return nil
	}
	variant := *base
	variant.ResponseMode = responseModeDCAPIJWT
	return &variant
}
