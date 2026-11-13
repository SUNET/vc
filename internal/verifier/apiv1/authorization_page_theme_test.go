package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/verifier/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A named theme used to win over an operator's primary_color, because the
// template emitted the configured colors first and the theme's second. The
// handler now resolves the pair before the template sees it, so the override
// is an override. docs/DIGITAL_CREDENTIALS_API.md documents exactly this
// combination.
func TestAuthorizeResolvesThemeColorsWithTheOverrideWinning(t *testing.T) {
	for _, tc := range []struct {
		name           string
		theme          string
		primaryColor   string
		secondaryColor string
		wantPrimary    string
		wantSecondary  string
	}{
		{
			name:          "a theme with no override uses the theme's own pair",
			theme:         "purple",
			wantPrimary:   "#805ad5",
			wantSecondary: "#553c9a",
		},
		{
			name:          "an override beats the theme that would have chosen the color",
			theme:         "purple",
			primaryColor:  "#1e40af",
			wantPrimary:   "#1e40af",
			wantSecondary: "#553c9a",
		},
		{
			name:           "both overridden",
			theme:          "blue",
			primaryColor:   "#1e40af",
			secondaryColor: "#1e3a8a",
			wantPrimary:    "#1e40af",
			wantSecondary:  "#1e3a8a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			client, mockDB := CreateTestClientWithMock(t, nil)
			client.cfg.Verifier.PublicURL = "https://verifier.example.com"
			client.cfg.Verifier.Outbound.OIDCProvider.SessionDuration = 900
			client.cfg.Verifier.AuthorizationPageCSS.Theme = tc.theme
			client.cfg.Verifier.AuthorizationPageCSS.PrimaryColor = tc.primaryColor
			client.cfg.Verifier.AuthorizationPageCSS.SecondaryColor = tc.secondaryColor

			client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid", "profile"}))

			require.NoError(t, mockDB.Clients.Create(ctx, &db.Client{
				ClientID:      "theme-client",
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"code"},
				AllowedScopes: []string{"openid", "profile"},
			}))

			resp, err := client.Authorize(ctx, &AuthorizeRequest{
				ResponseType:        "code",
				ClientID:            "theme-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               strings.Join([]string{"openid", "profile"}, " "),
				State:               "theme-state",
				Nonce:               "theme-nonce",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			})
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, tc.wantPrimary, resp.PrimaryColor)
			assert.Equal(t, tc.wantSecondary, resp.SecondaryColor)
			assert.Equal(t, tc.theme, resp.Theme)
		})
	}
}
