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
	client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: model.RemoteTypeEduAPI}}
	return client
}

func TestPrepareIssuance_AuthenticSourcePersonID(t *testing.T) {
	t.Run("an external API scope keeps the id on the server side", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{EducationOfferingID: "co-2"}},
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

func TestPrepareIssuance_ExternalAPI(t *testing.T) {
	eduOffering := &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{EducationOfferingID: "co-2"}}

	t.Run("an eduapi block is kept on the server side", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             eduOffering,
			IdentityMatch:           portalMatch(),
		})
		require.NoError(t, err)

		stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{IssuerState: reply.IssuerState})
		require.NoError(t, err)
		require.NotNil(t, stored.ExternalAPI)
		require.NotNil(t, stored.ExternalAPI.EduAPI)
		assert.Equal(t, "co-2", stored.ExternalAPI.EduAPI.EducationOfferingID)

		offer, err := json.Marshal(reply.CredentialOffer)
		require.NoError(t, err)
		assert.NotContains(t, string(offer), "co-2", "the offer is wallet-controlled and must not carry the offering")
	})

	t.Run("external_api on a datastore scope is refused", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeScope,
			ExternalAPI:   eduOffering,
			IdentityMatch: portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external_api")
	})

	t.Run("a block that does not match the remote type is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)
		client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: model.RemoteTypeOEAPI}}

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             eduOffering,
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not \"eduapi\"")
	})

	t.Run("an oeapi block is kept on a oeapi remote", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)
		client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: model.RemoteTypeOEAPI}}

		reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{CourseOfferingID: "co-2", ProgrammeOfferingID: "po-1"}},
			IdentityMatch:           portalMatch(),
		})
		require.NoError(t, err)

		stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{IssuerState: reply.IssuerState})
		require.NoError(t, err)
		require.NotNil(t, stored.ExternalAPI.OEAPI)
		assert.Equal(t, "co-2", stored.ExternalAPI.OEAPI.CourseOfferingID)
		assert.Equal(t, "po-1", stored.ExternalAPI.OEAPI.ProgrammeOfferingID)
	})

	t.Run("two blocks are refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{}, OEAPI: &cache.OEAPIParams{}},
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "one block")
	})

	t.Run("an external API scope without external_api is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external_api")
	})

	t.Run("an empty external_api object is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{},
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external_api")
	})

	t.Run("an eduapi block without an offering id is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{}},
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "education_offering_id")
	})

	t.Run("an oeapi block without any offering id is refused", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)
		client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: model.RemoteTypeOEAPI}}

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{}},
			IdentityMatch:           portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "offering_id")
	})

	t.Run("an oeapi block with only a course offering id is accepted", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)
		client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: model.RemoteTypeOEAPI}}

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:                   challengeExternalScope,
			AuthenticSourcePersonID: "p-lisa",
			ExternalAPI:             &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{CourseOfferingID: "co-2"}},
			IdentityMatch:           portalMatch(),
		})
		require.NoError(t, err)
	})
}
