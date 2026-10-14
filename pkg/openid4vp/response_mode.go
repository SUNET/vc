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

// WithDCAPIRequest returns a copy of r as the browser's Digital Credentials
// API requires it, with the three delivery-dependent fields adjusted and
// nothing else changed.
//
// For a session that serves both channels, the two requests must be the same
// request seen through different delivery paths: everything a wallet checks
// (client_id, nonce, client_metadata, the DCQL query) has to agree, or the
// channels ask for different things and only one of them is what the user
// consented to.
//
// The exceptions are response_mode, response_uri and expected_origins, and
// they are the same exception three times: each says HOW the request is
// delivered and answered, which is the one thing that does differ.
//
// A dc_api response returns inside the browser call, so the request carries
// no response_uri at all (OpenID4VP 1.0 Appendix A.2). Copying one over
// named an endpoint this channel is never answered at - a parameter the
// wallet is entitled to act on.
//
// expected_origins is the other direction: a SIGNED dc_api request must
// carry it (Appendix A.3), because it is what lets the wallet bind the
// request to the web origin that invoked it. Without it a conforming wallet
// may refuse the request outright, and one that does not refuse has lost the
// check that stops a request being replayed from another page. The link
// channel has no origin to name, which is why this is set here rather than
// on the object both channels share.
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
func (r *RequestObject) WithDCAPIRequest(expectedOrigin string) *RequestObject {
	if r == nil {
		return nil
	}
	variant := *r
	variant.ResponseMode = ResponseModeDCAPIJWT

	// A fresh slice, not an append to the original's: the copy is shallow,
	// so appending could write into a backing array the link-channel object
	// still points at.
	if expectedOrigin != "" {
		variant.ExpectedOrigins = []string{expectedOrigin}
	}

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

// WithInteractiveAuthorization returns a copy of r as OpenID4VCI 1.1
// Interactive Authorization requires it.
//
// The draft defines the request by difference: "the same as for requests
// passed to the Digital Credentials API ... except" the response mode, and
// except that expected_origins, if present, carries only the derived Origin
// of the Authorization Challenge Endpoint. So this is WithDCAPIRequest with
// the response mode replaced, and deliberately not a second construction of
// the same object - the two channels have to stay the same request seen
// through different delivery paths.
//
// responseMode is passed in rather than taken from the constants here
// because its spelling is configurable (CS01_07); it is expected to be one
// of ResponseModeIAPost or ResponseModeIAPostJWT, or whatever a deployment
// has renamed those to.
//
// The copy is SHALLOW, with the same constraint on callers that
// WithDCAPIRequest documents: treat both objects as immutable once created.
func (r *RequestObject) WithInteractiveAuthorization(responseMode, expectedOrigin string) *RequestObject {
	variant := r.WithDCAPIRequest(expectedOrigin)
	if variant == nil {
		return nil
	}
	variant.ResponseMode = responseMode
	return variant
}
