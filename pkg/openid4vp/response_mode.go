package openid4vp

// The response modes RequestObject.ResponseMode accepts.
//
// The authoritative list for validation is the oneof rule in that field's
// struct tag, which a Go tag cannot build from these constants. The two are
// therefore kept in step by TestResponseModeConstantsMatchOneofTag, which
// reads the tag back and compares it to this set, rather than by the
// declaration itself.
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
//
// The copy is SHALLOW, and that is a constraint on callers rather than an
// incidental detail: every reference-typed field - pointers, slices, maps -
// is shared with the original, not just the client_metadata pointer. Both
// objects must therefore be treated as immutable once created. Mutating
// either, including appending to one of its slices, either shows up in the
// other or silently stops doing so when a backing array is reallocated, and
// the two channels would then be asking for different things.
//
// That suits the only caller, which caches both and serves them read-only.
// A caller that needs to mutate one wants a deep copy, not this.
func (r *RequestObject) WithDCAPIResponseMode() *RequestObject {
	if r == nil {
		return nil
	}
	variant := *r
	variant.ResponseMode = ResponseModeDCAPIJWT
	return &variant
}
