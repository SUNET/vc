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

	// The two Interactive Authorization modes (OpenID4VCI 1.1). The
	// response goes back to the Authorization Challenge Endpoint the
	// request arrived from, inside an openid4vp_response parameter, so a
	// request using either carries NO response_uri.
	//
	// Spelled as the normative TEXT of the 1.1 draft spells them. Its
	// change log claims a rename to iae_post that none of its normative
	// sections apply, which is reported as openid/OpenID4VCI#811 and
	// recorded by WE BUILD CS-01 as NOTE CS01_07.
	//
	// Constants, not configuration. CS01_07 asks implementations to keep
	// the spelling switchable, and doing that properly means the
	// classifier below, this oneof tag and the request builders all
	// reading one configured value - which belongs with the code that
	// builds and receives these requests, not here. Until then this is
	// the normative spelling and nothing pretends otherwise.
	ResponseModeIAPost    = "ia_post"
	ResponseModeIAPostJWT = "ia_post.jwt"
)

// IsInteractiveAuthorization reports whether mode is one of the two
// Interactive Authorization response modes, which answer to the
// Authorization Challenge Endpoint rather than to a response_uri.
//
// Matches the constants above, so it recognises the normative spelling
// only. When the spelling becomes configurable this has to read the same
// configured values, or a deployment that switched it would find its own
// requests unclassified.
func IsInteractiveAuthorization(mode string) bool {
	return mode == ResponseModeIAPost || mode == ResponseModeIAPostJWT
}

// WithDCAPIResponseMode returns a copy of r carrying the response mode the
// browser's Digital Credentials API requires, with the two
// delivery-dependent fields adjusted and nothing else changed.
//
// For a session that serves both channels, the two requests must be the same
// request seen through different delivery paths: everything a wallet checks
// (client_id, nonce, client_metadata, the DCQL query) has to agree, or the
// channels ask for different things and only one of them is what the user
// consented to.
//
// The exceptions are response_mode and response_uri, and they are the same
// exception twice: both say HOW the response is delivered, which is the one
// thing that does differ. A dc_api response returns inside the browser call,
// so the request carries no response_uri at all (OpenID4VP 1.0 Appendix
// A.2). Copying one over named an endpoint this channel is never answered
// at - a parameter the wallet is entitled to act on.
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

	// A dc_api response returns inside the browser call, so the request
	// carries no response_uri (OpenID4VP 1.0 Appendix A.2). Copying the
	// direct-post object left one on it: a parameter the wallet is
	// entitled to act on, naming an endpoint this channel will never be
	// answered at.
	//
	// This is the one field that must NOT survive the copy, and it is the
	// exception that proves the rest of the doc comment above - everything
	// else has to agree across the two channels, or they are asking for
	// different things.
	variant.ResponseURI = ""

	return &variant
}
