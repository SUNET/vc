package httphelpers

import "testing"

func TestIsOIDCEndpoint(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Existing OIDC/OAuth2 endpoints
		{"/.well-known/openid-configuration", true},
		{"/op/jwks", true},
		{"/op/register", true},
		{"/op/token", true},
		{"/op/userinfo", true},
		{"/oidcrp/callback", true},
		{"/samlsp/acs", true},
		{"/op/par", true},

		// OID4VCI endpoints (issue #437)
		{"/nonce", true},
		{"/credential", true},
		{"/credential-offer/abc123", true},
		{"/deferred_credential", true},
		{"/notification", true},

		// Non-OIDC endpoints should return false
		{"/api/v1/users", false},
		{"/health", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isOIDCEndpoint(tt.path); got != tt.want {
				t.Errorf("isOIDCEndpoint(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
