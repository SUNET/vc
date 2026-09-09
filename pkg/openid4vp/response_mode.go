package openid4vp

// The response modes RequestObject.ResponseMode accepts, kept beside the
// field and its own oneof validation so the two cannot drift.
//
// Which of these is correct depends on how the request reaches the wallet,
// not on configuration: a dc_api mode is defined only for a request handed
// to the browser's Digital Credentials API, where the response returns
// inside that call and the mdoc session transcript binds to the calling
// origin. A request delivered as a link or QR code has neither, so a wallet
// cannot answer in that mode and is right to refuse - see SUNET/vc#652,
// where one request object served both channels.
const (
	ResponseModeFormPost      = "form_post"
	ResponseModeDirectPost    = "direct_post"
	ResponseModeDirectPostJWT = "direct_post.jwt"
	ResponseModeDCAPIJWT      = "dc_api.jwt"
)

// WithDCAPIResponseMode returns a copy of r carrying the response mode the
// browser's Digital Credentials API requires, and nothing else changed.
//
// For a session that serves both channels, the two requests must be the same
// request seen through different delivery paths: everything a wallet checks
// (client_id, nonce, response_uri, client_metadata, the DCQL query) has to
// agree, or the channels ask for different things and only one of them is
// what the user consented to.
//
// A copy of the whole struct rather than a rebuilt literal, so a field added
// to RequestObject cannot be set on one channel and forgotten on the other.
// Pointer fields are shared, deliberately: the wallet must see the same
// client_metadata either way.
func (r *RequestObject) WithDCAPIResponseMode() *RequestObject {
	if r == nil {
		return nil
	}
	variant := *r
	variant.ResponseMode = ResponseModeDCAPIJWT
	return &variant
}
