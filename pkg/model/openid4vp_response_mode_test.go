package model

import (
	"strings"
	"testing"
)

// TestOIDCRelyingPartyResponseMode pins SUNET/vc#652: a request object served
// behind a QR code or same-device link must never carry a dc_api mode,
// whatever the Digital Credentials API is configured to do.
func TestOIDCRelyingPartyResponseMode(t *testing.T) {
	verifier := func(dcEnable bool, dcMode, ownMode string) *Verifier {
		v := &Verifier{
			DigitalCredentials: DigitalCredentialsConfig{Enable: dcEnable, ResponseMode: dcMode},
			Inbound:            VerifierInbound{OpenID4VP: &OpenID4VPConfig{ResponseMode: ownMode}},
		}
		return v
	}

	for _, tc := range []struct {
		name string
		v    *Verifier
		want string
	}{
		{
			// The reported case: DC API on, response_mode at its dc_api.jwt
			// default, wallet gets a mode it cannot answer in.
			name: "dc_api.jwt default becomes direct_post.jwt",
			v:    verifier(true, "dc_api.jwt", ""),
			want: ResponseModeDirectPostJWT,
		},
		{
			// Encryption must survive the mapping - dropping to direct_post
			// here would silently unencrypt the response.
			name: "a profiled dc_api spelling keeps its encryption",
			v:    verifier(true, "w3c_dc_api.jwt", ""),
			want: ResponseModeDirectPostJWT,
		},
		{
			name: "an unencrypted dc_api mode maps to direct_post",
			v:    verifier(true, "dc_api", ""),
			want: ResponseModeDirectPost,
		},
		{
			// The documented workaround keeps working unchanged.
			name: "an explicit direct_post.jwt is left alone",
			v:    verifier(true, "direct_post.jwt", ""),
			want: ResponseModeDirectPostJWT,
		},
		{
			name: "DC API disabled is direct_post",
			v:    verifier(false, "dc_api.jwt", ""),
			want: ResponseModeDirectPost,
		},
		{
			// The decoupled setting wins over the legacy derivation.
			name: "the flow's own setting takes precedence",
			v:    verifier(true, "dc_api.jwt", ResponseModeDirectPost),
			want: ResponseModeDirectPost,
		},
		{
			name: "nil verifier does not panic",
			v:    nil,
			want: ResponseModeDirectPost,
		},
		{
			name: "nil inbound config falls back",
			v:    &Verifier{DigitalCredentials: DigitalCredentialsConfig{Enable: true, ResponseMode: "dc_api.jwt"}},
			want: ResponseModeDirectPostJWT,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.v.OIDCRelyingPartyResponseMode()
			if got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
			// Substring, not prefix: the resolver maps on strings.Contains,
			// so a profiled spelling like w3c_dc_api.jwt has to be caught
			// here too - a prefix check would have missed the one case in
			// this table that carries that shape.
			if strings.Contains(got, "dc_api") {
				t.Fatalf("a dc_api mode must never reach this flow, got %q", got)
			}
		})
	}
}
