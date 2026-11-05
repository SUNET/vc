package apiv1

import (
	"strings"
	"testing"

	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInteractionTypeFollowsTheSameSelectorAsAuthorize covers a scope
// configured in two data sources at once, which LookupCredentialSources is
// explicitly built to return.
//
// /authorize resolves such a scope through authproviders.Selector, which
// takes the FIRST source whose provider is actually running. The challenge
// endpoint has to reach the same answer: asking "is there an openid4vp
// source anywhere in the list" instead makes it demand a presentation for a
// scope the browser flow serves with OIDC, and auth_via_web is then
// unreachable for precisely the deployments that configured both.
func TestInteractionTypeFollowsTheSameSelectorAsAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name        string
		oidcRunning bool
		want        string
	}{
		{
			name:        "OIDC running, so the datastore source wins and the browser does the work",
			oidcRunning: true,
			want:        "urn:openid:dcp:ia:auth_via_web",
		},
		{
			name:        "OIDC not running, so the Selector falls through to the presentation source",
			oidcRunning: false,
			want:        "urn:openid:dcp:ia:openid4vp_presentation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)
			client.authProviderSelector = authproviders.NewSelector(false, tc.oidcRunning)

			// The same scope in two sources. Datastore is looked up first,
			// so it is the one the Selector reaches first.
			client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
				AuthProvider:    model.AuthProviderOIDC,
				AuthenticSource: "authentic-source",
				AuthScopes: map[string]model.AuthScopeEntry{
					challengeAuthScope: {AuthClaims: []string{"given_name", "family_name"}},
				},
			}
			client.cfg.APIGW.DataSources.Presentation.Scopes = map[string]model.PresentationScope{
				challengeScope: {
					AuthProvider: model.AuthProviderOpenID4VP,
					From: map[string]model.PresentedCredential{
						challengeAuthScope: {RequiredClaims: map[string][]string{"given_name": nil, "family_name": nil}},
					},
				},
			}

			req := initialChallenge(t)
			req.CodeChallenge = strings.Repeat("c", 43)
			req.CodeChallengeMethod = "S256"

			challenge := challengeErr(t, client, req)
			require.Equal(t, errInsufficientAuthorization, challenge.ErrorCode)
			assert.Equal(t, tc.want, challenge.InteractionTypeRequired)
		})
	}
}

// TestInteractionTypeRefusesWithoutASelector: the endpoint must not guess
// which provider a scope runs on. Guessing is what produced the bug above,
// and a deployment that fails to wire the Selector has to be told so, not
// quietly served the wrong interaction.
func TestInteractionTypeRefusesWithoutASelector(t *testing.T) {
	client := newChallengeClient(t)
	client.authProviderSelector = nil

	_, err := client.OAuthAuthorizationChallenge(t.Context(), initialChallenge(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine the required interaction",
		"an unwired selector must refuse, not fall back to a guess")
}
