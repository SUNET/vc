package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func credMetaClient(t *testing.T, emit bool) *Client {
	t.Helper()
	return &Client{
		cfg: &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
			EmitCredentialMetadataOnResponse: &emit,
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"pid": {CredentialMetadata: &openid4vci.CredentialMetadata{
					Display: []openid4vci.CredentialMetadataDisplay{{Name: "Personal ID", Locale: "en-US"}},
				}},
				"pid_1_8": {CredentialMetadata: &openid4vci.CredentialMetadata{
					Display: []openid4vci.CredentialMetadataDisplay{{Name: "Personal ID 1.8", Locale: "en-US"}},
				}},
				"no_metadata": {},
			},
		},
	}
}

func displayName(t *testing.T, m *openid4vci.CredentialMetadata) string {
	t.Helper()
	require.NotNil(t, m)
	require.NotEmpty(t, m.Display)
	return m.Display[0].Name
}

func TestCredentialMetadataForResponse(t *testing.T) {
	t.Run("off by default, nothing is echoed", func(t *testing.T) {
		assert.Nil(t, credMetaClient(t, false).credentialMetadataForResponse("pid", "pid"))
	})

	t.Run("on, the scope's metadata is echoed", func(t *testing.T) {
		got := credMetaClient(t, true).credentialMetadataForResponse("pid", "")
		assert.Equal(t, "Personal ID", displayName(t, got))
	})

	t.Run("the configuration named in the request wins over the scope", func(t *testing.T) {
		// The credential was minted from the named configuration, so
		// describing the scope's would describe a different credential
		// than the one in the same response - worse than describing none.
		got := credMetaClient(t, true).credentialMetadataForResponse("pid", "pid_1_8")
		assert.Equal(t, "Personal ID 1.8", displayName(t, got))
	})

	t.Run("an unknown configuration falls back to the scope", func(t *testing.T) {
		got := credMetaClient(t, true).credentialMetadataForResponse("pid", "not-a-configuration")
		assert.Equal(t, "Personal ID", displayName(t, got))
	})

	t.Run("a configuration carrying no metadata echoes nothing", func(t *testing.T) {
		assert.Nil(t, credMetaClient(t, true).credentialMetadataForResponse("no_metadata", ""))
	})

	t.Run("no issuer metadata at all is not a panic", func(t *testing.T) {
		emit := true
		client := &Client{cfg: &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
			EmitCredentialMetadataOnResponse: &emit,
		}}}}
		assert.Nil(t, client.credentialMetadataForResponse("pid", "pid"))
	})
}

// The member must be absent from the wire when it is nil, not present and
// null: a 1.0 wallet that validates the response shape should see exactly
// what it saw before this change.
func TestCredentialResponseOmitsEmptyCredentialMetadata(t *testing.T) {
	body, err := json.Marshal(&openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{{Credential: "ey..."}},
	})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "credential_metadata")

	body, err = json.Marshal(&openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{{Credential: "ey..."}},
		CredentialMetadata: &openid4vci.CredentialMetadata{
			Display: []openid4vci.CredentialMetadataDisplay{{Name: "Personal ID", Locale: "en-US"}},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"credential_metadata"`)
	assert.Contains(t, string(body), `"Personal ID"`)
}
