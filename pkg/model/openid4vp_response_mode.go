package model

import (
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// The two response modes a wallet reached by QR code or same-device link can
// actually use. Aliases of openid4vp's, which owns RequestObject.ResponseMode
// and its validation - defined there so the constants and the accepted set
// cannot drift apart.
const (
	ResponseModeDirectPost    = openid4vp.ResponseModeDirectPost
	ResponseModeDirectPostJWT = openid4vp.ResponseModeDirectPostJWT
)

// OIDCRelyingPartyResponseMode returns the response mode for request objects
// served behind the QR code and the same-device link.
//
// It never returns a dc_api mode. Those exist only for a request delivered
// through the browser's Digital Credentials API (OpenID4VP 1.0 Appendix A):
// the response comes back inside the browser call and the session transcript
// binds to the calling origin. A request that arrives as a link has neither,
// so a wallet cannot answer in that mode and is correct to refuse - which it
// does only after the user has chosen credentials and signed, so the failure
// lands at the worst possible moment (SUNET/vc#652).
//
// Precedence:
//
//   - verifier.inbound.openid4vp.response_mode, when set. This is the setting
//     that belongs to this flow.
//   - otherwise the legacy derivation from digital_credentials.response_mode,
//     kept so a deployment that worked yesterday still works today. That knob
//     names the Digital Credentials API and is read by the browser-side flow
//     for its own purposes; steering this flow with it was the bug. A dc_api
//     value maps to the direct_post equivalent that preserves whether the
//     response is encrypted, so a deployment relying on dc_api.jwt does not
//     silently drop to an unencrypted response.
func (v *Verifier) OIDCRelyingPartyResponseMode() string {
	if v == nil {
		return ResponseModeDirectPost
	}

	if v.Inbound.OpenID4VP != nil && v.Inbound.OpenID4VP.ResponseMode != "" {
		// Mapped, not returned verbatim. Config validation restricts this
		// field to the two direct_post modes, but this method is exported on
		// an exported struct, so it can be reached with a config that never
		// went through validation - a test, or anything constructing a
		// Verifier directly. The invariant this method documents has to hold
		// for those callers too, or it is not an invariant.
		return linkDeliverableResponseMode(v.Inbound.OpenID4VP.ResponseMode)
	}

	if !v.DigitalCredentials.Enable {
		return ResponseModeDirectPost
	}

	configured := v.DigitalCredentials.ResponseMode
	if configured == "" {
		// The field defaults to dc_api.jwt, so an empty value means defaults
		// were never applied. Treat it as that default would be treated.
		return ResponseModeDirectPostJWT
	}
	return linkDeliverableResponseMode(configured)
}

// linkDeliverableResponseMode maps any response mode onto one a wallet
// reached by link or QR code can actually answer in, preserving whether the
// response is encrypted.
//
// The return is always direct_post or direct_post.jwt - the only two modes
// this flow's /verification/oidc-direct_post endpoint handles. Nothing
// passes through unexamined: it previously returned any non-dc_api value
// verbatim, which let form_post, or any unrecognised string, out of a
// function whose whole purpose is to guarantee a deliverable mode. Config
// validation would reject those, but this file exists precisely because the
// exported method above can be reached with a config that never went
// through it.
//
// Encryption is inferred from the .jwt suffix, so a profiled or future
// spelling keeps whichever it asked for rather than silently dropping to an
// unencrypted response.
func linkDeliverableResponseMode(mode string) string {
	switch mode {
	case ResponseModeDirectPost, ResponseModeDirectPostJWT:
		return mode
	}
	if strings.HasSuffix(mode, ".jwt") {
		return ResponseModeDirectPostJWT
	}
	return ResponseModeDirectPost
}
