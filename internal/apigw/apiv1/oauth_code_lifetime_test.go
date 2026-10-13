package apiv1

import (
	"strings"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizationCodeTTLFitsTheAuthContextLifetime holds the two deadlines
// to the store that has to hold them.
//
// ExtendExpiry moves a logical deadline; MongoDB's TTL index is anchored to
// created_at and is not moved by it. If the sum ever grew past
// AuthContextTTL, /authorize would start advertising codes whose context the
// store has already deleted - and nothing else in the build would notice,
// because the memory store used in tests has no such anchor.
func TestAuthorizationCodeTTLFitsTheAuthContextLifetime(t *testing.T) {
	assert.LessOrEqual(t, requestURITTL+authorizationCodeTTL, apigwcache.AuthContextTTL,
		"a request_uri's life plus the code's must fit inside the authorization context's")
}

// TestAuthorizeExtendsTheCodeDeadlinePastTheRequestURI is the bug itself: one
// ExpiresAt was serving both as the request_uri's deadline and as the
// authorization code's, so a code was dead a minute after PAR however long
// the browser leg took.
func TestAuthorizeExtendsTheCodeDeadlinePastTheRequestURI(t *testing.T) {
	for _, tc := range []struct {
		name string
		// open returns the request_uri a browser leg starts from.
		open func(t *testing.T, client *Client) string
	}{
		{
			name: "from /op/par",
			open: func(t *testing.T, client *Client) string {
				reply, err := client.OAuthPar(t.Context(), &openid4vci.PARRequest{
					ClientID:            "wallet-1",
					Scope:               challengeScope,
					ResponseType:        "code",
					RedirectURI:         "https://wallet.example.com/cb",
					CodeChallenge:       strings.Repeat("c", 43),
					CodeChallengeMethod: "S256",
				})
				require.NoError(t, err)
				return reply.RequestURI
			},
		},
		{
			name: "from the auth_via_web interaction",
			open: func(t *testing.T, client *Client) string {
				req := initialChallenge(t)
				req.CodeChallenge = strings.Repeat("c", 43)
				req.CodeChallengeMethod = "S256"
				return challengeErr(t, client, req).RequestURI
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)
			// Browser-mediated, which is what both paths above need: PAR
			// refuses nothing here, and the challenge endpoint answers with
			// auth_via_web only for a scope with no openid4vp source.
			client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
				AuthProvider:    model.AuthProviderOIDC,
				AuthenticSource: "authentic-source",
			}

			requestURI := tc.open(t, client)
			require.NotEmpty(t, requestURI)

			opened, err := client.cacheService.AuthContext.Get(t.Context(),
				&cache.AuthorizationContext{RequestURI: requestURI})
			require.NoError(t, err)
			requestURIDeadline := opened.ExpiresAt
			require.LessOrEqual(t, requestURIDeadline, time.Now().Add(requestURITTL).Unix(),
				"the request_uri itself is short-lived, and stays so")

			_, err = client.OAuthAuthorize(t.Context(), &openid4vci.AuthorizeRequest{RequestURI: requestURI})
			require.NoError(t, err)

			consumed, err := client.cacheService.AuthContext.Get(t.Context(),
				&cache.AuthorizationContext{RequestURI: requestURI})
			require.NoError(t, err)

			assert.Greater(t, consumed.ExpiresAt, requestURIDeadline,
				"consuming the request_uri must hand the code its own deadline, "+
					"or the browser leg eats the code's whole life")
			assert.GreaterOrEqual(t, consumed.ExpiresAt,
				time.Now().Add(authorizationCodeTTL).Add(-5*time.Second).Unix(),
				"and that deadline is authorizationCodeTTL away, not a few seconds")
		})
	}
}

// TestExtendExpiryNeverShortens: /authorize is reachable more than once
// before consent, so an extension that could move a deadline backwards would
// let a second visit cut short a code the first one had already lengthened.
func TestExtendExpiryNeverShortens(t *testing.T) {
	client := newChallengeClient(t)

	far := time.Now().Add(time.Hour).Unix()
	require.NoError(t, client.cacheService.AuthContext.Save(t.Context(), &cache.AuthorizationContext{
		SessionID:  "session-1",
		RequestURI: "urn:ietf:params:oauth:request_uri:extend-1",
		ExpiresAt:  far,
	}))

	require.NoError(t, client.cacheService.AuthContext.ExtendExpiry(t.Context(),
		&cache.AuthorizationContext{RequestURI: "urn:ietf:params:oauth:request_uri:extend-1"},
		time.Now().Add(time.Minute).Unix()))

	got, err := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{RequestURI: "urn:ietf:params:oauth:request_uri:extend-1"})
	require.NoError(t, err)
	assert.Equal(t, far, got.ExpiresAt, "an earlier deadline must leave the stored one alone")
}
