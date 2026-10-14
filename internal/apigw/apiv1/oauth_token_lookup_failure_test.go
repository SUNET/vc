package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flakyAuthContextStore fails exactly the pre-consumption lookup - a Get
// by Code - and behaves normally for everything else, which is what a
// transient read failure against MongoDB looks like from here.
type flakyAuthContextStore struct {
	cache.AuthContextStore
	err error
}

func (f *flakyAuthContextStore) Get(ctx context.Context, query *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	if query != nil && query.Code != "" {
		return nil, f.err
	}
	return f.AuthContextStore.Get(ctx, query)
}

// The lookup that checks an Interactive Authorization code against the key
// its exchange was opened under runs BEFORE the code is consumed, and
// consumption is irreversible.
//
// Treating a store failure as "no binding to check" therefore lets a
// request carrying the wrong key burn a bound code: the authoritative
// check after consumption still refuses the token, but the legitimate
// wallet's code is gone and nothing re-issues it. "Absent" and "could not
// be read" must not be the same answer.
func TestOAuthToken_StoreFailureDoesNotBurnTheCode(t *testing.T) {
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	thiefKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, code := newIATokenClient(t, thumbprintOf(t, walletKey))
	healthy := client.cacheService.AuthContext
	client.cacheService.AuthContext = &flakyAuthContextStore{
		AuthContextStore: healthy,
		err:              errors.New("connection reset by peer"),
	}

	_, err = client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     "wallet-1",
		RedirectURI:  "https://wallet.example.com/cb",
		CodeVerifier: "unused-but-present",
		DPOP:         tokenDPoPProof(t, thiefKey),
	})
	require.Error(t, err)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode,
		"a store that could not answer must produce a server error, not a silent skip")

	// The whole point: the wallet's code survived the outage.
	client.cacheService.AuthContext = healthy
	survived, lookupErr := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{Code: code})
	require.NoError(t, lookupErr)
	require.NotNil(t, survived)
	assert.False(t, survived.Forfeited, "the code must not have been consumed while the store was failing")
}
