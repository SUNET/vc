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
	for _, tt := range []struct {
		name            string
		emit            bool
		scope           string
		configurationID string
		want            string // display name, or "" for no metadata at all
	}{
		{name: "off by default, nothing is echoed", scope: "pid", configurationID: "pid"},
		{name: "on, the scope's metadata is echoed", emit: true, scope: "pid", want: "Personal ID"},
		// The credential was minted from the configuration named in the
		// REQUEST, so echoing the scope's metadata would describe a
		// different credential than the one in the same response.
		{name: "the request's configuration wins over the scope", emit: true, scope: "pid", configurationID: "pid_1_8", want: "Personal ID 1.8"},
		{name: "an unknown configuration falls back to the scope", emit: true, scope: "pid", configurationID: "nope", want: "Personal ID"},
		{name: "a configuration carrying no metadata echoes nothing", emit: true, scope: "no_metadata"},
		{name: "a scope that is not configured at all echoes nothing", emit: true, scope: "not-a-scope"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := credMetaClient(t, tt.emit).credentialMetadataForResponse(tt.scope, tt.configurationID)
			if tt.want == "" {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, displayName(t, got))
		})
	}
}

// Assembled where it is actually assembled. Deleting the field from the
// response literal used to leave every test above green while it vanished
// from the wire, because they all test the selector.
func TestNewCredentialResponseCarriesTheMetadata(t *testing.T) {
	credentials := []openid4vci.Credential{{Credential: "ey..."}}

	on := credMetaClient(t, true).newCredentialResponse(credentials, "pid", "")
	require.Equal(t, credentials, on.Credentials)
	assert.Equal(t, "Personal ID", displayName(t, on.CredentialMetadata))

	off := credMetaClient(t, false).newCredentialResponse(credentials, "pid", "")
	require.Equal(t, credentials, off.Credentials)
	assert.Nil(t, off.CredentialMetadata)
}

func TestCredentialMetadataForResponseWithoutIssuerMetadata(t *testing.T) {
	emit := true
	client := &Client{cfg: &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		EmitCredentialMetadataOnResponse: &emit,
	}}}}
	assert.Nil(t, client.credentialMetadataForResponse("pid", "pid"))
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
