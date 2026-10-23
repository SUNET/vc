package apiv1

import (
	"context"
	"net/http"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declineClient is a verifier with one live session, which is all an
// error response needs: it carries no presentation to verify.
func declineClient(t *testing.T, state string) (*Client, *cache.AuthorizationContext) {
	t.Helper()
	ctx := context.Background()

	client, _ := CreateTestClientWithMock(t, nil)
	notifyService, _ := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	client.notify = notifyService

	authCtx := &cache.AuthorizationContext{
		SessionID: "declining-session",
		State:     state,
		Nonce:     "nonce",
		ClientID:  "x509_san_dns:verifier.example.com",
		Status:    cache.SessionStatusAwaitingPresentation,
	}
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, authCtx))
	return client, authCtx
}

// The live failure: the user declines, the engine POSTs a plain
// error form to response_uri, and the verifier answered 500 "failed to
// get KID from request: failed to parse JWT header: unexpected end of
// JSON input" because it looked for a JWE header in an empty string.
//
// OpenID4VP 1.0 section 8.3.1 permits an unencrypted error response even
// for direct_post.jwt, and section 8.2's example is exactly this form.
func TestDirectPostAcceptsAPlainDecline(t *testing.T) {
	ctx := context.Background()
	client, _ := declineClient(t, "declined-state")

	reply, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
		Error:            "access_denied",
		ErrorDescription: "consent-declined",
		State:            "declined-state",
	})
	require.NoError(t, err, "a declined presentation is an outcome, not a server failure")
	require.NotNil(t, reply)

	stored, err := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: "declined-state"})
	require.NoError(t, err)
	assert.Equal(t, cache.SessionStatusError, stored.Status, "the session must be terminal")
	assert.Equal(t, "access_denied", stored.Error)
	assert.Equal(t, "consent-declined", stored.ErrorDescription)
}

// The half that actually unsticks the UI. /ui/completion reports a
// missing response code as "pending", so recording the decline is not
// enough on its own - the session has to have an outcome that is
// neither pending nor complete.
func TestDeclinedSessionHasATerminalOutcome(t *testing.T) {
	ctx := context.Background()
	client, authCtx := declineClient(t, "declined-state")

	before, err := client.SessionOutcome(ctx, authCtx.SessionID)
	require.NoError(t, err)
	require.False(t, before.Declined(), "the session has not been answered yet")
	require.Empty(t, before.ResponseCode)

	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
		Error: "access_denied", State: "declined-state",
	})
	require.NoError(t, err)

	after, err := client.SessionOutcome(ctx, authCtx.SessionID)
	require.NoError(t, err)
	assert.True(t, after.Declined(), "the UI would poll pending forever")
	assert.Equal(t, "access_denied", after.Error)
	assert.Empty(t, after.ResponseCode, "a declined session has no response code")
}

// state is what ties an error response to a request. OpenID4VP 1.0
// section 14.3.2: the Verifier SHOULD check that it corresponds to a
// recent Authorization Request.
func TestDirectPostDeclineRequiresAKnownState(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct{ name, state string }{
		{"no state at all", ""},
		{"a state this verifier is not waiting for", "someone-elses-state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, authCtx := declineClient(t, "declined-state")

			_, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
				Error: "access_denied", State: tc.state,
			})
			require.Error(t, err, "accepting this would let anyone who can reach response_uri end a session")

			shaped := helpers.NewErrorFromError(err)
			assert.Equal(t, http.StatusBadRequest, shaped.HTTPStatus)

			// And the real session is untouched: silently answering 200
			// would leave it pending while reporting success.
			stored, getErr := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: authCtx.State})
			require.NoError(t, getErr)
			assert.Empty(t, stored.Error, "an unrelated session must not be ended by this")
		})
	}
}

// Neither a presentation nor an error is the caller's mistake, and it
// used to reach GetKID and come back as a 500.
func TestDirectPostWithNeitherPresentationNorErrorIsABadRequest(t *testing.T) {
	ctx := context.Background()
	client, _ := declineClient(t, "declined-state")

	_, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{})
	require.Error(t, err)

	shaped := helpers.NewErrorFromError(err)
	assert.Equal(t, http.StatusBadRequest, shaped.HTTPStatus, "a malformed request is not a server failure")
	assert.False(t, shaped.IsUnclassified(), "the caller gets a req_id and no idea what to fix")
	assert.NotContains(t, err.Error(), "JWT header",
		"the old message described a JWE the caller never claimed to send")
}

// A wallet that CAN encrypt returns its error the way section 5.6 says
// it SHOULD - "Both successful and error responses SHOULD be returned
// using the supplied Response Mode" - so the same outcome arrives inside
// the envelope. It has no vp_token, and would otherwise be reported as a
// malformed presentation.
func TestDirectPostAcceptsAnEncryptedDecline(t *testing.T) {
	ctx := context.Background()
	client, _ := declineClient(t, "declined-state")

	reply, err := client.directPostError(ctx, "access_denied", "consent-declined", "declined-state")
	require.NoError(t, err)
	require.NotNil(t, reply)

	stored, err := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: "declined-state"})
	require.NoError(t, err)
	assert.Equal(t, cache.SessionStatusError, stored.Status)
}
