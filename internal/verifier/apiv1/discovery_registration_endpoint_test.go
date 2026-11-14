package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveryConfigWithRegistration builds the smallest config
// GetDiscoveryMetadata needs, carrying the dynamic_registration block given.
func discoveryConfigWithRegistration(registration *model.DynamicRegistrationConfig) *model.Cfg {
	return &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:              "https://verifier.example.com",
					SubjectType:         "public",
					SubjectSalt:         "test-salt",
					DynamicRegistration: registration,
				},
			},
			Inbound: model.VerifierInbound{
				OpenID4VP: &model.OpenID4VPConfig{},
			},
		},
	}
}

// What the discovery document says has to match what the server serves. An
// advertised registration_endpoint that answers 404 sends every client that
// reads the document down a path that cannot work, and RFC 8414 Section 2
// describes the member as the endpoint's URL, not as a URL that may or may
// not be one.
func TestDiscoveryMetadataRegistrationEndpoint(t *testing.T) {
	ctx := t.Context()

	t.Run("advertised when registration is offered", func(t *testing.T) {
		for _, tt := range []struct {
			name         string
			registration *model.DynamicRegistrationConfig
		}{
			{name: "no dynamic_registration block", registration: nil},
			{name: "explicitly enabled", registration: &model.DynamicRegistrationConfig{Enabled: new(true)}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				client, _ := CreateTestClientWithMock(t, discoveryConfigWithRegistration(tt.registration))

				metadata, err := client.GetDiscoveryMetadata(ctx)
				require.NoError(t, err)

				assert.Equal(t, "https://verifier.example.com/register", metadata.RegistrationEndpoint,
					"an OP that serves /register must keep advertising it")
			})
		}
	})

	t.Run("omitted when registration is closed", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(t, discoveryConfigWithRegistration(
			&model.DynamicRegistrationConfig{Enabled: new(false)},
		))

		metadata, err := client.GetDiscoveryMetadata(ctx)
		require.NoError(t, err)

		assert.Empty(t, metadata.RegistrationEndpoint)

		// Empty is not enough: the member has to be absent from the
		// served document, which is what the omitempty tag is for.
		serialized, err := json.Marshal(metadata)
		require.NoError(t, err)

		var document map[string]any
		require.NoError(t, json.Unmarshal(serialized, &document))

		assert.NotContains(t, document, "registration_endpoint",
			"a closed OP must not advertise a registration_endpoint that answers 404")
	})
}
