package apiv1

import (
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openPreparedExchange prepares an issuance, has the wallet resume it, and
// returns the ids a test needs to continue and to poll.
func openPreparedExchange(t *testing.T, client *Client) (issuanceID, authSession string) {
	t.Helper()
	client.cacheService.IssuanceStatus = apigwcache.NewTestMemoryCache[*apigwcache.IssuanceStatusRecord](time.Hour)

	prepared, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: portalMatch(),
	})
	require.NoError(t, err)

	req := initialChallenge(t)
	req.Scope = ""
	req.IssuerState = prepared.IssuerState
	opened := challengeErr(t, client, req)
	require.NotEmpty(t, opened.AuthSession)
	return prepared.IssuanceID, opened.AuthSession
}

func pollIssuance(t *testing.T, client *Client, issuanceID string) *IssuanceStatusReply {
	t.Helper()
	reply, err := client.IssuanceStatus(t.Context(), &IssuanceStatusRequest{
		IssuanceID:      issuanceID,
		AuthenticSource: "authentic-source",
		Scope:           challengeScope,
	})
	require.NoError(t, err)
	return reply
}

// Once the auth_session is claimed it cannot be reopened, so an error after
// that point ends the issuance and the status has to say so.
func TestAuthorizationChallenge_ErrorAfterClaimMarksTheIssuanceFailed(t *testing.T) {
	client := newChallengeClient(t)
	issuanceID, authSession := openPreparedExchange(t, client)
	require.Equal(t, IssuanceStatusAuthorizationStarted, pollIssuance(t, client, issuanceID).Status)

	oauthErr := oauthErrFromChallenge(t, client, continueExchange(t, authSession, "not a json object"))
	assert.Equal(t, "invalid_request", oauthErr.ErrorCode)

	status := pollIssuance(t, client, issuanceID)
	assert.Equal(t, IssuanceStatusFailed, status.Status)
	assert.Equal(t, errDescChallengeFailed, status.EventDescription,
		"the description is fixed text, not the cause")
}

// A request refused before the claim leaves the exchange alive, so the
// issuance has not failed.
func TestAuthorizationChallenge_ErrorBeforeClaimLeavesTheIssuanceStarted(t *testing.T) {
	client := newChallengeClient(t)
	issuanceID, authSession := openPreparedExchange(t, client)

	oauthErr := oauthErrFromChallenge(t, client, continueExchange(t, authSession, ""))
	assert.Equal(t, "invalid_request", oauthErr.ErrorCode)

	assert.Equal(t, IssuanceStatusAuthorizationStarted, pollIssuance(t, client, issuanceID).Status)
}
