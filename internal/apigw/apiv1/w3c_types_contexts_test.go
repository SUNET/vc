package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/require"
)

// TestW3CTypesAndContextsComeFromOneScope: CredentialConfigurationsSupported
// is keyed by SCOPE, the configuration id comes from the request and the scope
// comes from the token - so reading types from the named configuration and
// contexts from the authorised scope paired two different scopes.
//
// A caller authorised for A naming configuration B got B's types with A's
// contexts: terms those contexts do not define, which expand to relative IRIs
// and match no query a verifier builds from B's credential_type_values. The
// credential is issued, looks right, and can never be presented - which is the
// "these three fields only work as a set" failure, reached through the request
// rather than through the configuration file.
func TestW3CTypesAndContextsComeFromOneScope(t *testing.T) {
	client := &Client{
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"diploma": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "DiplomaCredential"},
				CredentialContexts: []string{"https://example.org/diploma"},
			},
			"licence": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "LicenceCredential"},
				CredentialContexts: []string{"https://example.org/licence"},
			},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"diploma": {CredentialDefinition: &openid4vci.CredentialDefinition{
					Type: []string{"VerifiableCredential", "DiplomaCredential"},
				}},
				"licence": {CredentialDefinition: &openid4vci.CredentialDefinition{
					Type: []string{"VerifiableCredential", "LicenceCredential"},
				}},
			},
		},
	}

	t.Run("a configuration naming another scope takes that scope's contexts too", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "licence")
		require.Contains(t, types, "LicenceCredential")
		require.Equal(t, []string{"https://example.org/licence"}, contexts,
			"the contexts must define the types, so both come from the configuration that was named")
		require.NotContains(t, contexts, "https://example.org/diploma")
	})

	t.Run("no configuration id uses the authorised scope for both", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "")
		require.Contains(t, types, "DiplomaCredential")
		require.Equal(t, []string{"https://example.org/diploma"}, contexts)
	})

	t.Run("an unknown configuration id falls back to the authorised scope", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "no-such-configuration")
		require.Contains(t, types, "DiplomaCredential")
		require.Equal(t, []string{"https://example.org/diploma"}, contexts)
	})
}
