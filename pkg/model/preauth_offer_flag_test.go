package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allow_preauth_offer must not reach the wallet-initiated path.
//
// handlers_oauth.go rejects a PAR/authorize request whose scope has
// auth_provider preauth, so that a wallet cannot start a flow for a
// credential issued only by offer. The flag says something different -
// that an offer MAY ALSO be minted - and a scope carrying it is still
// login-gated, so its wallet-initiated flow must keep working exactly as
// before.
//
// The structural reason it cannot leak is that CredentialSource carries
// AuthProvider and nothing else. Pinned here because that is a property
// of a type anyone may extend, and extending it with the flag would
// silently turn every flagged scope into one wallets may no longer start.
func TestAllowPreAuthOfferDoesNotReachTheAuthorizationPath(t *testing.T) {
	sources := &DataSources{Datastore: DatastoreConfig{Scopes: map[string]DatastoreScope{
		"diploma": {AuthProvider: AuthProviderOIDC, AllowPreAuthOffer: true},
		"pid":     {AuthProvider: AuthProviderPreAuth},
	}}}

	t.Run("a flagged login-gated scope still reports its real auth provider", func(t *testing.T) {
		got, err := sources.LookupCredentialSources("diploma")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, AuthProviderOIDC, got[0].AuthProvider,
			"reporting preauth here would make the authorization path refuse a wallet-initiated flow this scope still supports")
	})

	t.Run("a real preauth scope is unchanged", func(t *testing.T) {
		got, err := sources.LookupCredentialSources("pid")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, AuthProviderPreAuth, got[0].AuthProvider,
			"the wallet-initiated rejection depends on this and must not move")
	})
}
