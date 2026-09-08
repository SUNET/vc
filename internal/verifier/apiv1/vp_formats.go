package apiv1

import "github.com/SUNET/vc/pkg/openid4vp"

// vpFormatsOrDefault returns the operator's configured vp_formats_supported,
// or a default naming the formats this verifier can actually verify.
//
// OpenID4VP 1.0 section 11.1 makes vp_formats_supported REQUIRED in
// client_metadata when the wallet cannot learn it another way, but
// verifier.preferred_vp_formats has no default and is absent from the sample
// config - so a deployment that never set it sent a request object missing a
// required member, and nothing anywhere said so.
//
// The default deliberately carries no algorithm arrays. Those are optional
// within each format object, and this verifier has no algorithm allowlist to
// report: it verifies with whatever key the credential's issuer chain
// provides. Naming a set here would either understate what is accepted (and
// stop a wallet presenting something that would in fact verify) or overstate
// it (and invite something that will not). An operator who does need to
// constrain algorithms sets preferred_vp_formats explicitly, which this then
// leaves entirely alone.
func vpFormatsOrDefault(configured *openid4vp.VPFormatsSupported) *openid4vp.VPFormatsSupported {
	if configured != nil {
		return configured
	}
	return &openid4vp.VPFormatsSupported{
		SDJWT:   &openid4vp.SDJWTVCFormat{},
		MsoMdoc: &openid4vp.MsoMdocFormat{},
	}
}
