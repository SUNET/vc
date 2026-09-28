package helpers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/go-playground/validator/v10"
)

// TestDynamicRegistrationAuthModeMatchesConfig pins the fail-open case.
//
// Mode defaults to "open", and the middleware pass-through for "open" never
// looks at the rest of the block - so auth settings with no mode to activate
// them leave dynamic client registration unprotected while looking configured.
func TestDynamicRegistrationAuthModeMatchesConfig(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := &model.DynamicRegistrationJWTAuthConfig{
		JWKSURI:  "https://auth.example.com/jwks.json",
		Issuer:   "https://auth.example.com",
		Audience: "vc-verifier-register",
	}

	for _, tc := range []struct {
		name    string
		cfg     model.DynamicRegistrationAuthConfig
		wantTag string
	}{
		{
			name:    "jwt block with no mode",
			cfg:     model.DynamicRegistrationAuthConfig{JWT: jwtCfg},
			wantTag: "auth_config_requires_non_open_mode",
		},
		{
			name:    "jwt block with mode open",
			cfg:     model.DynamicRegistrationAuthConfig{Mode: "open", JWT: jwtCfg},
			wantTag: "auth_config_requires_non_open_mode",
		},
		{
			name:    "token file with mode open",
			cfg:     model.DynamicRegistrationAuthConfig{Mode: "open", StaticBearerTokenFile: "/run/secrets/tok"},
			wantTag: "auth_config_requires_non_open_mode",
		},
		{
			// The guard asks whether the operator wrote the key, not
			// whether what they wrote is usable. Trimming first made a
			// whitespace-only path look absent under the default mode, so
			// the exact configuration this exists to catch - auth settings
			// with no mode to activate them - slipped through and left
			// /register open. Under mode: static the same value is
			// rejected, and an intent that fails one way must not pass the
			// other.
			name:    "whitespace-only token file with no mode",
			cfg:     model.DynamicRegistrationAuthConfig{StaticBearerTokenFile: " "},
			wantTag: "auth_config_requires_non_open_mode",
		},
		{
			name:    "whitespace-only token file with mode open",
			cfg:     model.DynamicRegistrationAuthConfig{Mode: "open", StaticBearerTokenFile: "\t\n"},
			wantTag: "auth_config_requires_non_open_mode",
		},
		{
			name: "jwt block with mode jwt",
			cfg:  model.DynamicRegistrationAuthConfig{Mode: "jwt", JWT: jwtCfg},
		},
		{
			name: "token file with mode static",
			cfg:  model.DynamicRegistrationAuthConfig{Mode: "static", StaticBearerTokenFile: "/run/secrets/tok"},
		},
		{
			name: "open with nothing else set",
			cfg:  model.DynamicRegistrationAuthConfig{Mode: "open"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.cfg)
			if tc.wantTag == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("expected validation errors, got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == tc.wantTag {
					return
				}
			}
			t.Fatalf("expected a %q failure, got: %v", tc.wantTag, err)
		})
	}
}

// TestDynamicRegistrationJWTClockSkewBound pins the accepted range.
//
// The upper bound is one second short of go-oidc's fixed five-minute nbf
// leeway: the same knob that relaxes exp shrinks that leeway by the same
// amount, so at or past 300 a token with a legitimately future nbf starts
// being rejected - the opposite of what raising a skew tolerance is for.
// Negative values would otherwise be silently treated as disabled.
func TestDynamicRegistrationJWTClockSkewBound(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	base := func(skew int) model.DynamicRegistrationJWTAuthConfig {
		return model.DynamicRegistrationJWTAuthConfig{
			JWKSURI:          "https://auth.example.com/jwks.json",
			Issuer:           "https://auth.example.com",
			Audience:         "vc-verifier-register",
			ClockSkewSeconds: &skew,
		}
	}

	for _, tc := range []struct {
		skew       int
		wantReject bool
	}{
		{-1, true},
		{0, false},
		{60, false},
		{299, false},
		{300, true},
		{3600, true},
	} {
		t.Run(fmt.Sprintf("skew_%d", tc.skew), func(t *testing.T) {
			err := v.Struct(base(tc.skew))
			if tc.wantReject && err == nil {
				t.Fatalf("clock_skew_seconds=%d must be rejected", tc.skew)
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("clock_skew_seconds=%d must be accepted, got: %v", tc.skew, err)
			}
		})
	}
}

// TestDynamicRegistrationJWTEndpointsRequireHTTPS pins the scheme on the two
// URLs that decide whether a registration token is believed.
//
// The key set is the trust root for jwt mode: whoever serves it decides which
// signatures verify. Fetched over plaintext, that is anyone on the network
// path, who can then swap in their own keys and mint a token this verifier
// accepts - so the whole check reduces to "someone on the wire said yes".
//
// Private and loopback addresses stay allowed, unlike the httpsurl tag used
// for client-supplied URIs: an in-cluster issuer is a normal deployment, not
// an SSRF attempt, and this value comes from the operator's own config file.
func TestDynamicRegistrationJWTEndpointsRequireHTTPS(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		jwksURI    string
		issuer     string
		wantReject bool
	}{
		{"both https", "https://auth.example.com/jwks.json", "https://auth.example.com", false},
		{"plaintext jwks", "http://auth.example.com/jwks.json", "https://auth.example.com", true},
		{"plaintext issuer", "https://auth.example.com/jwks.json", "http://auth.example.com", true},
		{"uppercase scheme accepted", "HTTPS://auth.example.com/jwks.json", "https://auth.example.com", false},
		{"private address over https", "https://10.0.0.7:8443/jwks.json", "https://10.0.0.7:8443", false},
		{"loopback over https", "https://127.0.0.1:8443/jwks.json", "https://127.0.0.1:8443", false},
		{"plaintext loopback still rejected", "http://127.0.0.1:8443/jwks.json", "https://auth.example.com", true},
		{"no host", "https:///jwks.json", "https://auth.example.com", true},
		{"not a url at all", "auth.example.com/jwks.json", "https://auth.example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(model.DynamicRegistrationJWTAuthConfig{
				JWKSURI:  tc.jwksURI,
				Issuer:   tc.issuer,
				Audience: "vc-verifier-register",
			})
			if tc.wantReject && err == nil {
				t.Fatalf("jwks_uri=%q issuer=%q must be rejected", tc.jwksURI, tc.issuer)
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("jwks_uri=%q issuer=%q must be accepted, got: %v", tc.jwksURI, tc.issuer, err)
			}
		})
	}
}
