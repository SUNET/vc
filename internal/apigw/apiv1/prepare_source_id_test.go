package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const challengeExternalScope = "sis_enrollment"

// newExternalAPIChallengeClient serves challengeExternalScope from a remote,
// authenticated by a presented credential.
func newExternalAPIChallengeClient(t *testing.T) *Client {
	t.Helper()
	client := newChallengeClient(t)

	client.cfg.Common.CredentialMetadata[challengeExternalScope] = client.cfg.Common.CredentialMetadata[challengeScope]
	client.cfg.APIGW.DataSources.ExternalAPI = model.ExternalAPIConfig{Scopes: map[string]model.ExternalAPIScope{
		challengeExternalScope: {
			Remote:       "sis",
			AuthProvider: model.AuthProviderOpenID4VP,
			AuthScopes: map[string]model.AuthScopeEntry{
				challengeAuthScope: {AuthClaims: []string{"given_name", "family_name"}},
			},
		},
	}}
	return client
}

func TestPrepareIssuance_AuthenticSourcePersonID(t *testing.T) {
	t.Run("an external API scope keeps the id on the server side", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			IdentityMatch:           portalMatch(),
		})
		require.NoError(t, err)

		stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{IssuerState: reply.IssuerState})
		require.NoError(t, err)
		assert.Equal(t, "p-lisa", stored.AuthenticSourcePersonID)
		assert.Equal(t, "sis", stored.RemoteName)
		assert.Equal(t, string(model.DataSourceExternalAPI), stored.DataSource)

		offer, err := json.Marshal(reply.CredentialOffer)
		require.NoError(t, err)
		assert.NotContains(t, string(offer), "p-lisa", "the offer is wallet-controlled and must not carry the id")
	})

	t.Run("an external API scope without an id is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeExternalScope,
			IdentityMatch: portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentic_source_person_id")
	})

	t.Run("an id on a datastore scope is refused", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeScope,
			AuthenticSourcePersonID: "p-lisa",
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentic_source_person_id")
	})
}
