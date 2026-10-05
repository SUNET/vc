package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/require"
)

func selectScopeClient() *Client {
	return &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"diploma": {Format: "ldp_vc", CredentialTypes: []string{"VerifiableCredential", "DiplomaCredential"}},
			"licence": {Format: "ldp_vc", CredentialTypes: []string{"VerifiableCredential", "LicenceCredential"}},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"diploma": {Format: "ldp_vc"},
				"licence": {Format: "ldp_vc"},
			},
		},
	}
}

// TestSelectScope: matchScope takes the FIRST authorised scope with
// credential metadata, which is not necessarily the one the request asked
// for. Resolving only the TYPES from the named configuration while the
// document and the issuer's Scope still came from matchScope's answer
// assembled a credential out of two scopes - B's types over A's claims,
// labelled A - which is the exact failure this PR exists to prevent, just
// reached from a different direction.
func TestSelectScope(t *testing.T) {
	client := selectScopeClient()

	// Both authorised, "diploma" first, and the request selects "licence"
	// through a credential_identifier.
	authCtx := &cache.AuthorizationContext{
		Scopes: []string{"diploma", "licence"},
		AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
			CredentialConfigurationID: "licence",
			CredentialIdentifiers:     []string{"licence-1"},
		}},
	}

	t.Run("the selected configuration decides the scope", func(t *testing.T) {
		scope, configID, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "licence-1"}, authCtx)
		require.NoError(t, err)
		require.Equal(t, "licence", scope,
			"the document and the issuer's Scope must follow the configuration the request selected")
		require.Equal(t, "licence", configID)
	})

	t.Run("credential_configuration_id does the same", func(t *testing.T) {
		scope, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialConfigurationID: "licence"},
			&cache.AuthorizationContext{Scopes: []string{"diploma", "licence"}})
		require.NoError(t, err)
		require.Equal(t, "licence", scope)
	})

	// The control: without a named configuration, matchScope's answer
	// stands. Without this the test above would pass against a function
	// that always returned the last scope.
	t.Run("no named configuration leaves matchScope's answer", func(t *testing.T) {
		scope, configID, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "bare-1"},
			&cache.AuthorizationContext{
				Scopes: []string{"diploma", "licence"},
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
					Format:                "ldp_vc",
					CredentialIdentifiers: []string{"bare-1"},
				}},
			})
		require.NoError(t, err)
		require.Equal(t, "diploma", scope, "a format-based entry names no configuration to prefer")
		require.Empty(t, configID)
	})

	// The token says which scopes the wallet may have. An identifier
	// resolving outside that set is an authorisation failure, not a
	// preference - taking it would issue a credential the token never
	// authorised.
	t.Run("a configuration outside the authorized scopes is refused", func(t *testing.T) {
		_, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "licence-1"},
			&cache.AuthorizationContext{
				Scopes:               []string{"diploma"},
				AuthorizationDetails: authCtx.AuthorizationDetails,
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not among the authorized scopes")
	})
}
