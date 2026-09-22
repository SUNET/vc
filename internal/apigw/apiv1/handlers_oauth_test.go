package apiv1

import (
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthPar_PreAuthScopeRejected(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	clientID := "wallet-1"
	redirectURI := "https://wallet.example.com/callback"

	client := &Client{
		log: log,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				PublicURL: "https://apigw.example.com",
				Delivery: model.APIGWDelivery{
					OpenID4VCI: model.OAuthServer{
						Clients: oauth2.Clients{
							clientID: {
								Type:         oauth2.ClientTypePublic,
								RedirectURIs: oauth2.RedirectURIs{redirectURI},
								Scopes:       []string{"micro_credential"},
							},
						},
					},
				},
				DataSources: model.DataSources{
					Datastore: model.DatastoreConfig{
						Scopes: map[string]model.DatastoreScope{
							"micro_credential": {AuthProvider: model.AuthProviderPreAuth},
						},
					},
				},
			},
		},
		cacheService: &apigwcache.Service{
			AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
		},
	}

	req := &openid4vci.PARRequest{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         "micro_credential",
		CodeChallenge: "test-challenge",
	}

	reply, err := client.OAuthPar(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeInvalidScope, oauthErr.ErrorCode)
}

func newTokenTestClient(t *testing.T, storedTXCode string) (*Client, string) {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	authContextStore := apigwcache.NewTestMemoryStore(10 * time.Minute)
	preAuthCode := "test-pre-auth-code"

	err = authContextStore.Save(t.Context(), &apigwcache.AuthorizationContext{
		SessionID:    preAuthCode,
		Code:         preAuthCode,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		Scopes:       []string{"pid"},
		AuthProvider: model.AuthProviderDatastore,
		DataSource:   string(model.DataSourceDatastore),
		TXCode:       storedTXCode,
	})
	require.NoError(t, err)

	client := &Client{
		log: log,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					OpenID4VCI: model.OAuthServer{
						TokenEndpoint: "https://apigw.example.com/token",
					},
				},
			},
		},
		cacheService: &apigwcache.Service{
			AuthContext: authContextStore,
		},
	}
	return client, preAuthCode
}

func TestOAuthToken_PreAuth_TXCodeMismatchRejected(t *testing.T) {
	client, code := newTokenTestClient(t, "123456")

	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
		TXCode:            "999999",
	})
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)

	// Wrong PIN must not burn the code
	stored, getErr := client.cacheService.AuthContext.Get(t.Context(), &apigwcache.AuthorizationContext{Code: code})
	require.NoError(t, getErr)
	assert.False(t, stored.Forfeited)
}

func TestOAuthToken_PreAuth_TXCodeMissingRejected(t *testing.T) {
	client, code := newTokenTestClient(t, "123456")

	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
	})
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
}

func TestOAuthToken_PreAuth_TXCodeUnexpectedRejected(t *testing.T) {
	client, code := newTokenTestClient(t, "")

	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
		TXCode:            "123456",
	})
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
}

func TestOAuthToken_PreAuth_TXCodeAttemptsLockout(t *testing.T) {
	client, code := newTokenTestClient(t, "123456")

	for range apigwcache.MaxTXCodeAttempts {
		reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:         openid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: code,
			TXCode:            "999999",
		})
		require.Error(t, err)
		assert.Nil(t, reply)
	}

	stored, getErr := client.cacheService.AuthContext.Get(t.Context(), &apigwcache.AuthorizationContext{Code: code})
	require.NoError(t, getErr)
	assert.Equal(t, apigwcache.MaxTXCodeAttempts, stored.TXCodeAttempts)
	assert.False(t, stored.Forfeited, "code must not be forfeited until another wrong attempt trips the cap")

	// The next wrong-PIN attempt trips the cap and forfeits the code.
	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
		TXCode:            "999999",
	})
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)

	stored, getErr = client.cacheService.AuthContext.Get(t.Context(), &apigwcache.AuthorizationContext{Code: code})
	require.NoError(t, getErr)
	assert.True(t, stored.Forfeited, "code must be forfeited once the attempt budget is exhausted")
}

// TestOAuthToken_PreAuth_TXCodeSuccessDoesNotConsumeAttempts verifies that a
// successful PIN comparison does not debit the per-code attempt budget, so
// PIN-protected offers can still serve up to MaxPreAuthRedeemers wallets.
func TestOAuthToken_PreAuth_TXCodeSuccessDoesNotConsumeAttempts(t *testing.T) {
	client, code := newTokenTestClient(t, "123456")

	// Exhaust MaxTXCodeAttempts - 1 wrong attempts.
	for range apigwcache.MaxTXCodeAttempts - 1 {
		_, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:         openid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: code,
			TXCode:            "999999",
		})
		require.Error(t, err)
	}

	// A correct PIN must still succeed and must not consume the attempt budget.
	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
		TXCode:            "123456",
	})
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.NotEmpty(t, reply.AccessToken)

	// The counter must still show only the failed attempts.
	stored, getErr := client.cacheService.AuthContext.Get(t.Context(), &apigwcache.AuthorizationContext{Code: code})
	require.NoError(t, getErr)
	assert.Equal(t, apigwcache.MaxTXCodeAttempts-1, stored.TXCodeAttempts,
		"successful PIN comparison must not consume the attempt budget")
}
