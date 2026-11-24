package apiv1

import (
	"context"
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
	return withRemoteType(client, model.RemoteTypeEduAPI)
}

func TestPrepareIssuance_AuthenticSourcePersonID(t *testing.T) {
	t.Run("an external API scope keeps the id on the server side", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		reply, err := prepareExternal(client, eduOffering("co-2"))
		require.NoError(t, err)

		stored := storedContext(t, client, reply)
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

func eduOffering(id string) *cache.ExternalAPIParams {
	return &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{EducationOfferingID: id}}
}

// withRemoteType makes the scope's remote of the given type.
func withRemoteType(client *Client, typ model.RemoteType) *Client {
	client.cfg.APIGW.Remotes = map[string]model.Remote{"sis": {Type: typ}}
	return client
}

// prepareExternal prepares an issuance of the external API scope for Lisa.
func prepareExternal(client *Client, ext *cache.ExternalAPIParams) (*PrepareIssuanceReply, error) {
	return client.PrepareIssuance(context.Background(), &PrepareIssuanceRequest{
		Scope:                   challengeExternalScope,
		AuthenticSourcePersonID: "p-lisa",
		ExternalAPI:             ext,
		IdentityMatch:           portalMatch(),
	})
}

func storedContext(t *testing.T, client *Client, reply *PrepareIssuanceReply) *cache.AuthorizationContext {
	t.Helper()
	stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{IssuerState: reply.IssuerState})
	require.NoError(t, err)
	return stored
}

func TestPrepareIssuance_ExternalAPI(t *testing.T) {
	t.Run("an eduapi block is kept on the server side", func(t *testing.T) {
		client := newExternalAPIChallengeClient(t)

		reply, err := prepareExternal(client, eduOffering("co-2"))
		require.NoError(t, err)

		stored := storedContext(t, client, reply)
		require.NotNil(t, stored.ExternalAPI)
		require.NotNil(t, stored.ExternalAPI.EduAPI)
		assert.Equal(t, "co-2", stored.ExternalAPI.EduAPI.EducationOfferingID)

		offer, err := json.Marshal(reply.CredentialOffer)
		require.NoError(t, err)
		assert.NotContains(t, string(offer), "co-2", "the offer is wallet-controlled and must not carry the offering")
	})

	t.Run("an oeapi block is kept on a oeapi remote", func(t *testing.T) {
		client := withRemoteType(newExternalAPIChallengeClient(t), model.RemoteTypeOEAPI)

		reply, err := prepareExternal(client, &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{CourseOfferingID: "co-2", ProgrammeOfferingID: "po-1"}})
		require.NoError(t, err)

		stored := storedContext(t, client, reply)
		require.NotNil(t, stored.ExternalAPI.OEAPI)
		assert.Equal(t, "co-2", stored.ExternalAPI.OEAPI.CourseOfferingID)
		assert.Equal(t, "po-1", stored.ExternalAPI.OEAPI.ProgrammeOfferingID)
	})

	t.Run("an oeapi block with only a course offering id is accepted", func(t *testing.T) {
		client := withRemoteType(newExternalAPIChallengeClient(t), model.RemoteTypeOEAPI)

		_, err := prepareExternal(client, &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{CourseOfferingID: "co-2"}})
		require.NoError(t, err)
	})

	t.Run("external_api on a datastore scope is refused", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeScope,
			ExternalAPI:   eduOffering("co-2"),
			IdentityMatch: portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external_api")
	})

	refused := []struct {
		name       string
		remoteType model.RemoteType
		ext        *cache.ExternalAPIParams
		want       string
	}{
		{"a block that does not match the remote type", model.RemoteTypeOEAPI, eduOffering("co-2"), `not "eduapi"`},
		{"two blocks", model.RemoteTypeEduAPI, &cache.ExternalAPIParams{EduAPI: &cache.EduAPIParams{}, OEAPI: &cache.OEAPIParams{}}, "one block"},
		{"no external_api", model.RemoteTypeEduAPI, nil, "external_api"},
		{"an empty external_api object", model.RemoteTypeEduAPI, &cache.ExternalAPIParams{}, "external_api"},
		{"an eduapi block without an offering id", model.RemoteTypeEduAPI, eduOffering(""), "education_offering_id"},
		{"an oeapi block without any offering id", model.RemoteTypeOEAPI, &cache.ExternalAPIParams{OEAPI: &cache.OEAPIParams{}}, "offering_id"},
	}
	for _, tc := range refused {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			client := withRemoteType(newExternalAPIChallengeClient(t), tc.remoteType)

			_, err := prepareExternal(client, tc.ext)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
