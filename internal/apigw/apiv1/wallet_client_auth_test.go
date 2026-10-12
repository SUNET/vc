package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authErr runs authenticateOAuthClient and returns the OAuth error it
// produced, failing the test if it succeeded.
func authErr(t *testing.T, client *Client, req *walletClientAuth) *oauth2.OAuthError {
	t.Helper()
	got, err := client.authenticateOAuthClient(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, got)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	return oauthErr
}

// These pin the branches of the client-authentication block that are
// reachable without a wallet-attestation evaluator, so that moving it out
// of OAuthPar is a refactor with the behaviour written down rather than a
// refactor taken on trust.
func TestAuthenticateOAuthClient(t *testing.T) {
	configured := oauth2.Clients{
		"wallet-1": {
			Type:         oauth2.ClientTypePublic,
			RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/cb"},
			Scopes:       []string{"pid"},
		},
	}

	t.Run("a configured client is returned without touching attestation", func(t *testing.T) {
		client, _ := parLoggingClient(t, configured)

		got, err := client.authenticateOAuthClient(t.Context(), &walletClientAuth{
			ClientID:    "wallet-1",
			RedirectURI: "https://wallet.example.com/cb",
			Scope:       "pid",
			LogPrefix:   "TEST",
		})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, oauth2.ClientTypePublic, got.Type)
	})

	t.Run("the attestation header without its PoP is refused", func(t *testing.T) {
		// draft-ietf-oauth-attestation-based-client-auth §3.1: the header
		// form MUST carry a PoP. Checked before the evaluator is consulted,
		// so an unattested deployment still enforces it.
		client, _ := parLoggingClient(t, oauth2.Clients{})

		oauthErr := authErr(t, client, &walletClientAuth{
			ClientID:          "wallet-2",
			RedirectURI:       "https://wallet.example.com/cb",
			Scope:             "pid",
			ClientAttestation: "an-attestation-jwt",
			LogPrefix:         "TEST",
		})
		assert.Equal(t, oauth2.ErrCodeInvalidClient, oauthErr.ErrorCode)
		assert.Equal(t, 401, oauthErr.HTTPStatus)
		assert.Contains(t, oauthErr.ErrorDescription, "OAuth-Client-Attestation-PoP")
	})

	t.Run("the legacy form-body carrier does not demand a PoP", func(t *testing.T) {
		// It reaches the evaluator instead, which is absent here, so the
		// refusal is the generic one rather than the PoP message. That
		// difference is the whole point of the legacy path.
		client, _ := parLoggingClient(t, oauth2.Clients{})

		oauthErr := authErr(t, client, &walletClientAuth{
			ClientID:        "wallet-3",
			RedirectURI:     "https://wallet.example.com/cb",
			Scope:           "pid",
			ClientAssertion: "a-legacy-assertion",
			LogPrefix:       "TEST",
		})
		assert.Equal(t, oauth2.ErrCodeInvalidClient, oauthErr.ErrorCode)
		assert.NotContains(t, oauthErr.ErrorDescription, "OAuth-Client-Attestation-PoP")
	})

	t.Run("an unknown client with no attestation is refused", func(t *testing.T) {
		client, _ := parLoggingClient(t, oauth2.Clients{})

		oauthErr := authErr(t, client, &walletClientAuth{
			ClientID:    "wallet-4",
			RedirectURI: "https://wallet.example.com/cb",
			Scope:       "pid",
			LogPrefix:   "TEST",
		})
		assert.Equal(t, oauth2.ErrCodeInvalidClient, oauthErr.ErrorCode)
		assert.Equal(t, 401, oauthErr.HTTPStatus)
	})

	t.Run("the log prefix names the endpoint that asked", func(t *testing.T) {
		// Two endpoints authenticate the same wallets through this
		// function, so a rejection has to say which request produced it.
		//
		// Asserted on the MESSAGE, not on the client id: an earlier
		// version of this test looked for the entry by client_id, which
		// every such line carries whether or not it names the caller - so
		// it passed with the prefix absent entirely.
		client, readLog := parLoggingClient(t, configured)

		_, err := client.authenticateOAuthClient(t.Context(), &walletClientAuth{
			ClientID:    "wallet-1",
			RedirectURI: "https://wallet.example.com/cb",
			Scope:       "not-a-configured-scope",
			LogPrefix:   "CHALLENGE",
		})
		require.Error(t, err)

		entries := warnings(readLog())
		require.NotEmpty(t, entries, "a configured client rejected must still be reported")

		attributed := false
		for _, entry := range entries {
			if strings.Contains(entry.Message, "CHALLENGE:") {
				attributed = true
			}
		}
		assert.True(t, attributed, "the warning must name the endpoint that asked, got %v", entries)
	})

	t.Run("a different caller is named differently", func(t *testing.T) {
		// The other half: a prefix that is hardcoded, or dropped, would
		// pass the assertion above for every caller.
		client, readLog := parLoggingClient(t, configured)

		_, err := client.authenticateOAuthClient(t.Context(), &walletClientAuth{
			ClientID:    "wallet-1",
			RedirectURI: "https://wallet.example.com/cb",
			Scope:       "not-a-configured-scope",
			LogPrefix:   "PAR",
		})
		require.Error(t, err)

		for _, entry := range warnings(readLog()) {
			assert.NotContains(t, entry.Message, "CHALLENGE:")
			assert.Contains(t, entry.Message, "PAR:")
		}
	})
}
