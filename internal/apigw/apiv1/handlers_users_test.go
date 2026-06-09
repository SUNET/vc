package apiv1

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildAuthorizationRedirectURL tests the helper used by UserLookup to construct
// the authorization response redirect URL with code, state, and iss parameters.
func TestBuildAuthorizationRedirectURL(t *testing.T) {
	tests := []struct {
		name      string
		walletURI string
		code      string
		state     string
		iss       string
		wantCode  string
		wantState string
		wantISS   string
		wantExtra map[string]string // pre-existing query params that must survive
		wantErr   bool
	}{
		{
			name:      "plain redirect URI",
			walletURI: "https://wallet.example.com/callback",
			code:      "auth-code-123",
			state:     "state-xyz",
			iss:       "https://issuer.example.com",
			wantCode:  "auth-code-123",
			wantState: "state-xyz",
			wantISS:   "https://issuer.example.com",
		},
		{
			name:      "redirect URI with existing query params",
			walletURI: "https://wallet.example.com/callback?client_ref=abc&session=42",
			code:      "auth-code-456",
			state:     "state-abc",
			iss:       "https://issuer.example.com",
			wantCode:  "auth-code-456",
			wantState: "state-abc",
			wantISS:   "https://issuer.example.com",
			wantExtra: map[string]string{
				"client_ref": "abc",
				"session":    "42",
			},
		},
		{
			name:      "redirect URI with trailing slash",
			walletURI: "https://wallet.example.com/callback/",
			code:      "code-789",
			state:     "s1",
			iss:       "https://issuer.example.com",
			wantCode:  "code-789",
			wantState: "s1",
			wantISS:   "https://issuer.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAuthorizationRedirectURL(tt.walletURI, tt.code, tt.state, tt.iss)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			parsed, err := url.Parse(result)
			require.NoError(t, err)

			assert.Equal(t, tt.wantCode, parsed.Query().Get("code"))
			assert.Equal(t, tt.wantState, parsed.Query().Get("state"))
			assert.Equal(t, tt.wantISS, parsed.Query().Get("iss"))

			for k, v := range tt.wantExtra {
				assert.Equal(t, v, parsed.Query().Get(k),
					"pre-existing query param %q must be preserved", k)
			}
		})
	}
}
