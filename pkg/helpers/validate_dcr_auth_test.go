package helpers

import (
	"errors"
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
