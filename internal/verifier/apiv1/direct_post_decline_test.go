package apiv1

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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

// unreachableAuthContextStore answers every lookup the way a store whose
// backend is down does: with an operational error, not a miss. The
// distinction is the whole point - ErrNoDocuments means "no such state",
// anything else means "I cannot tell you".
type unreachableAuthContextStore struct {
	cache.AuthContextStore
	err error
}

func (s unreachableAuthContextStore) Get(context.Context, *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	return nil, s.err
}

// A wallet's error response must not be able to undo an outcome the
// session already has. Without the guard a late or replayed error
// overwrote a completed session's status while its VerifierResponseCode
// survived, so /ui/completion said "declined" and /ui/resume said
// "complete" for the same session - two answers, both read from stored
// state, with no way to tell which actually happened.
func TestDirectPostDeclineDoesNotOverwriteAnOutcome(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		arrange func(*cache.AuthorizationContext)
		status  cache.SessionStatus
		wantErr string
	}{
		{
			name: "a session that has already completed",
			arrange: func(a *cache.AuthorizationContext) {
				a.Status = cache.SessionStatusCompleted
				a.VerifierResponseCode = "response-code"
			},
			status:  cache.SessionStatusCompleted,
			wantErr: "",
		},
		{
			name: "a session that has already been declined",
			arrange: func(a *cache.AuthorizationContext) {
				a.Status = cache.SessionStatusError
				a.Error = "access_denied"
				a.ErrorDescription = "the first refusal"
			},
			status:  cache.SessionStatusError,
			wantErr: "access_denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, authCtx := declineClient(t, "declined-state")
			tc.arrange(authCtx)
			require.NoError(t, client.cacheService.AuthContext.Update(ctx, authCtx))

			// Answered, not refused: the wallet is told its POST was
			// received. Returning an error would invite it to retry
			// against a session that is over.
			reply, err := client.directPostError(ctx, "server_error", "a later, losing refusal", "declined-state")
			require.NoError(t, err)
			require.NotNil(t, reply)

			stored, err := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: "declined-state"})
			require.NoError(t, err)
			assert.Equal(t, tc.status, stored.Status, "the first outcome must stand")
			assert.Equal(t, tc.wantErr, stored.Error, "a later error response must not rewrite the recorded one")
			assert.NotEqual(t, "a later, losing refusal", stored.ErrorDescription)
		})
	}
}

// A backend that cannot answer is not an unknown state. Answering 400
// here tells a wallet its own request was malformed during an outage,
// and the real session stays pending with nobody retrying.
func TestDirectPostDeclineOnAnUnreachableBackendIsNotABadRequest(t *testing.T) {
	ctx := context.Background()
	client, _ := declineClient(t, "declined-state")
	client.cacheService.AuthContext = unreachableAuthContextStore{
		AuthContextStore: client.cacheService.AuthContext,
		err:              errors.New("connection refused"),
	}

	_, err := client.directPostError(ctx, "access_denied", "consent-declined", "declined-state")
	require.Error(t, err)

	shaped := helpers.NewErrorFromError(err)
	assert.Equal(t, http.StatusServiceUnavailable, shaped.HTTPStatus,
		"an outage must be retryable, not reported as the caller's mistake")
	assert.NotEqual(t, http.StatusBadRequest, shaped.HTTPStatus)
	assert.NotContains(t, err.Error(), "connection refused",
		"the wallet learns the verifier is unavailable, not what its backend is")
}

// The description is wallet-controlled input, and the model bounds it at
// 512 bytes. Save validates AFTER the fields are assigned, so mutating
// the stored document in place left a memory-backed deployment with the
// rejected value and a terminal status on the live session while a
// Mongo-backed one kept the old one - the same request, two outcomes,
// decided by the cache backend.
func TestDirectPostDeclineWithAnOversizedDescriptionLeavesTheSessionIntact(t *testing.T) {
	ctx := context.Background()
	client, _ := declineClient(t, "declined-state")

	_, err := client.directPostError(ctx, "access_denied", strings.Repeat("x", 513), "declined-state")
	require.Error(t, err, "a value the model refuses to store must not be reported as stored")

	stored, getErr := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: "declined-state"})
	require.NoError(t, getErr)
	assert.Equal(t, cache.SessionStatusAwaitingPresentation, stored.Status,
		"a failed save must not leave the session terminal")
	assert.Empty(t, stored.Error, "a failed save must not leave the session carrying a refusal")
	assert.Empty(t, stored.ErrorDescription, "the rejected value must not be readable from the live session")
}

// /ui/resume is what a reloaded tab asks. Before this it answered
// "pending" with the original QR for a request the user had already
// declined, so the two endpoints disagreed: /ui/completion said declined
// while /ui/resume offered the code again.
func TestUIResumeReportsADeclinedSession(t *testing.T) {
	ctx := context.Background()
	client, authCtx := declineClient(t, "declined-state")

	_, err := client.directPostError(ctx, "access_denied", "consent-declined", "declined-state")
	require.NoError(t, err)

	reply, err := client.UIResume(ctx, authCtx.SessionID)
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.Equal(t, UIResumeDeclined, reply.Status, "a reload must not rebuild the QR for a refused request")
	assert.Equal(t, "access_denied", reply.Error)
	assert.Equal(t, "consent-declined", reply.ErrorDescription)
	assert.Empty(t, reply.AuthorizationRequest, "there is nothing left to scan")
	assert.Empty(t, reply.ResponseCode, "a declined session has no response code")
}

// A declined context has been answered. Handing it to a fresh
// interaction would reuse the state and nonce the user just refused, and
// the decline recorded on it would then describe a request nobody made.
func TestDeclinedSessionIsNotReusedByANewInteraction(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	// A real interaction is needed here (not declineClient's bare
	// context) because the reuse path runs through UIInteraction, and
	// the decline it answers broadcasts on the notify service.
	notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	require.NoError(t, err)
	client.notify = notifyService

	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)
	require.NotEmpty(t, first.SessionID)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	require.NotEmpty(t, authCtx.State)
	require.True(t, isReusableAuthContext(authCtx), "the premise: it was reusable before the refusal")

	_, err = client.directPostError(ctx, "access_denied", "consent-declined", authCtx.State)
	require.NoError(t, err)

	declined, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	assert.False(t, isReusableAuthContext(declined), "a refused session is answered, not in flight")

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID,
		"a new request after a refusal must get its own session")

	// And the refusal still describes the request it was given, not the
	// new one.
	stillDeclined, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", stillDeclined.Error)
}

// The other direction of "first outcome wins". The deadline was the
// only thing checked before a presentation was accepted, so a wallet
// that posted credentials after the user had declined - a refusal and a
// presentation racing, or a replay - wrote a VerifierResponseCode onto a
// session whose Error and terminal status stayed put. /ui/completion
// then reported "declined" and /ui/resume "complete" for one session.
func TestVerificationDirectPostRefusesAnAlreadyAnsweredSession(t *testing.T) {
	ctx := t.Context()

	answeredSession := func(t *testing.T, decline bool) (*Client, string, string) {
		t.Helper()
		client, _ := CreateTestClientWithMock(t, nil)
		notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
		require.NoError(t, err)
		client.notify = notifyService

		sessionID, state := "answered-verification-session", "answered-state"
		session := pendingSession(sessionID, state, time.Now().Add(10*time.Minute).Unix())
		session.EphemeralEncryptionKeyID = sessionID
		require.NoError(t, client.cacheService.AuthContext.Save(ctx, session))

		if decline {
			_, err = client.directPostError(ctx, "access_denied", "consent-declined", state)
			require.NoError(t, err)
		}
		return client, sessionID, state
	}

	// The premise, so the test below is about the guard and not about a
	// verifier that refuses every presentation: the same session, the
	// same deadline, is not refused as answered while it is still live.
	t.Run("a live session is not refused as answered", func(t *testing.T) {
		client, sessionID, state := answeredSession(t, false)
		_, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
			Response: encryptedVPResponse(t, client, sessionID, state),
		})
		assert.NotErrorIs(t, err, ErrSessionAlreadyAnswered)
	})

	t.Run("a declined session refuses the presentation that follows", func(t *testing.T) {
		client, sessionID, state := answeredSession(t, true)

		_, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{
			Response: encryptedVPResponse(t, client, sessionID, state),
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionAlreadyAnswered)
		assert.NotErrorIs(t, err, ErrSessionExpired, "the deadline has not passed; the session was answered")

		stored, err := client.cacheService.AuthContext.GetByID(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, "access_denied", stored.Error, "the refusal must still be what this session says happened")
		assert.Empty(t, stored.VerifierResponseCode, "accepting it would have made the two UI endpoints disagree")
	})
}
