package apiv1

import (
	"testing"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrongPIN redeems the code with a PIN that is not the stored one and
// returns the OAuth error code the token endpoint answered with.
func wrongPIN(t *testing.T, client *Client, code string) string {
	t.Helper()
	reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
		GrantType:         openid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: code,
		TXCode:            "999999",
	})
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, 400, oauthErr.HTTPStatus, "the status is unchanged either way; only the error code moves")
	return oauthErr.ErrorCode
}

// withInvalidTXCodeError flips the 1.1 gate on the client's config.
func withInvalidTXCodeError(client *Client) *Client {
	on := true
	client.cfg.APIGW.Delivery.OpenID4VCICompat.EmitInvalidTXCodeError = &on
	return client
}

// OpenID4VCI 1.0 answers a wrong Transaction Code and a dead
// Pre-Authorized Code with the same invalid_grant, so a wallet cannot tell
// "the holder mistyped it, ask again" from "this offer is finished, get a
// new one". In a profile that requires a Transaction Code on every
// pre-authorized offer - WE BUILD CS-01 does - that is the most common
// error the flow produces, and the difference is one the holder sees.
func TestOAuthToken_InvalidTXCodeGate(t *testing.T) {
	t.Run("off: a wrong PIN is invalid_grant, as in 1.0", func(t *testing.T) {
		client, code := newTokenTestClient(t, "123456")
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, wrongPIN(t, client, code))
	})

	t.Run("on: a wrong PIN with attempts left is invalid_tx_code", func(t *testing.T) {
		client, code := newTokenTestClient(t, "123456")
		assert.Equal(t, oauth2.ErrCodeInvalidTXCode, wrongPIN(t, withInvalidTXCodeError(client), code))
	})

	t.Run("on: the attempt that exhausts the budget is invalid_grant", func(t *testing.T) {
		// This is the half that carries the meaning. Once the code is
		// forfeited there is nothing left to retry, so it must NOT look
		// retryable - a wallet that kept prompting would be asking the
		// holder for a PIN that can no longer be accepted.
		client, code := newTokenTestClient(t, "123456")
		withInvalidTXCodeError(client)

		for range apigwcache.MaxTXCodeAttempts {
			assert.Equal(t, oauth2.ErrCodeInvalidTXCode, wrongPIN(t, client, code),
				"attempts remain, so each of these is retryable")
		}

		assert.Equal(t, oauth2.ErrCodeInvalidGrant, wrongPIN(t, client, code),
			"the attempt that trips the cap forfeits the code")

		stored, err := client.cacheService.AuthContext.Get(t.Context(), &apigwcache.AuthorizationContext{Code: code})
		require.NoError(t, err)
		assert.True(t, stored.Forfeited)
	})

	t.Run("on: an already-forfeited code stays invalid_grant", func(t *testing.T) {
		client, code := newTokenTestClient(t, "123456")
		withInvalidTXCodeError(client)
		for range apigwcache.MaxTXCodeAttempts + 1 {
			wrongPIN(t, client, code)
		}
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, wrongPIN(t, client, code))
	})

	t.Run("on: an unknown code stays invalid_grant", func(t *testing.T) {
		client, _ := newTokenTestClient(t, "123456")
		withInvalidTXCodeError(client)

		reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:         openid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: "no-such-code",
			TXCode:            "123456",
		})
		require.Error(t, err)
		assert.Nil(t, reply)

		var oauthErr *oauth2.OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
	})

	t.Run("on: a missing or unexpected PIN stays invalid_request", func(t *testing.T) {
		// Already conformant in 1.0 and unchanged by 1.1; asserted so the
		// gate cannot quietly widen to cover it.
		client, code := newTokenTestClient(t, "123456")
		withInvalidTXCodeError(client)

		_, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:         openid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: code,
		})
		var oauthErr *oauth2.OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)

		noPINClient, noPINCode := newTokenTestClient(t, "")
		withInvalidTXCodeError(noPINClient)
		_, err = noPINClient.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:         openid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: noPINCode,
			TXCode:            "123456",
		})
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	})
}

// The accessor is nil-safe all the way down, because the token endpoint
// should not have to repeat the nil dance that three other call sites in
// this package already do not.
func TestEmitInvalidTXCodeErrorIsNilSafe(t *testing.T) {
	var nilCfg *model.Cfg
	assert.False(t, nilCfg.EmitInvalidTXCodeError())
	assert.False(t, (&model.Cfg{}).EmitInvalidTXCodeError())
	assert.False(t, (&model.Cfg{APIGW: &model.APIGW{}}).EmitInvalidTXCodeError())
}
