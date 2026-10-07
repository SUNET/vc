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
		scope, configID, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "licence-1"}, authCtx)
		require.NoError(t, err)
		require.Equal(t, "licence", scope,
			"the document and the issuer's Scope must follow the configuration the request selected")
		require.Equal(t, "licence", configID)
	})

	t.Run("credential_configuration_id does the same", func(t *testing.T) {
		scope, _, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialConfigurationID: "licence"},
			&cache.AuthorizationContext{Scopes: []string{"diploma", "licence"}})
		require.NoError(t, err)
		require.Equal(t, "licence", scope)
	})

	// A format-based authorization_details entry (OID4VCI 5.1.1) names a
	// FORMAT and no configuration, so there is no scope name to take.
	// matchScope's answer is the first authorised scope with metadata,
	// chosen without reference to the format - while the dispatch routes on
	// the format. Taking it meant issuing one scope's document and
	// configuration through another format's path.
	t.Run("a format-based entry picks the scope whose format matches", func(t *testing.T) {
		// Only "licence" is ldp_vc here, and it is NOT matchScope's first
		// answer - so this cannot pass by accident.
		mixed := selectScopeClient()
		mixed.cfg.Common.CredentialMetadata["diploma"] = &model.CredentialMetadata{Format: "dc+sd-jwt"}

		scope, configID, format, err := mixed.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "bare-1"},
			&cache.AuthorizationContext{
				Scopes: []string{"diploma", "licence"},
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
					Format:                "ldp_vc",
					CredentialIdentifiers: []string{"bare-1"},
				}},
			})
		require.NoError(t, err)
		require.Equal(t, "licence", scope, "the scope must be one configured for the requested format")
		require.Empty(t, configID, "a format-based entry names no configuration")
		require.Equal(t, "ldp_vc", format)
	})

	// Zero and several are both "this request does not identify a
	// credential", and guessing between them is how the mismatch above
	// happened.
	t.Run("a format matching several authorized scopes is refused", func(t *testing.T) {
		_, _, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "bare-1"},
			&cache.AuthorizationContext{
				Scopes: []string{"diploma", "licence"}, // both ldp_vc
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
					Format:                "ldp_vc",
					CredentialIdentifiers: []string{"bare-1"},
				}},
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "matches several authorized scopes")
	})

	t.Run("a format matching no authorized scope is refused", func(t *testing.T) {
		_, _, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "bare-1"},
			&cache.AuthorizationContext{
				Scopes: []string{"diploma", "licence"},
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
					Format:                "mso_mdoc",
					CredentialIdentifiers: []string{"bare-1"},
				}},
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no authorized scope is configured")
	})

	// sd-jwt has two spellings and they are the same format; a scope
	// configured as one must answer a request for the other.
	t.Run("sd-jwt spellings are the same format", func(t *testing.T) {
		sdjwt := selectScopeClient()
		sdjwt.cfg.Common.CredentialMetadata["diploma"] = &model.CredentialMetadata{Format: "dc+sd-jwt"}
		sdjwt.cfg.Common.CredentialMetadata["licence"] = &model.CredentialMetadata{Format: "mso_mdoc"}

		// "licence" first, so matchScope's answer is the WRONG one: this
		// cannot pass by the selection being skipped.
		scope, _, _, err := sdjwt.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "bare-1"},
			&cache.AuthorizationContext{
				Scopes: []string{"licence", "diploma"},
				AuthorizationDetails: []openid4vci.AuthorizationDetailsParameter{{
					Format:                "vc+sd-jwt",
					CredentialIdentifiers: []string{"bare-1"},
				}},
			})
		require.NoError(t, err)
		require.Equal(t, "diploma", scope, "dc+sd-jwt and vc+sd-jwt are one format")
	})

	// The token says which scopes the wallet may have. An identifier
	// resolving outside that set is an authorisation failure, not a
	// preference - taking it would issue a credential the token never
	// authorised.
	t.Run("a configuration outside the authorized scopes is refused", func(t *testing.T) {
		_, _, _, err := client.selectScope(
			&openid4vci.CredentialRequest{CredentialIdentifier: "licence-1"},
			&cache.AuthorizationContext{
				Scopes:               []string{"diploma"},
				AuthorizationDetails: authCtx.AuthorizationDetails,
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not among the authorized scopes")
	})
}
