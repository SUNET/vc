package apiv1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptedVPResponse builds what a direct_post.jwt wallet posts.
func encryptedVPResponse(t *testing.T, client *Client, sessionID, state string) string {
	t.Helper()

	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(t.Context(), sessionID)
	require.NoError(t, err)

	raw, err := json.Marshal(openid4vp.VPResponse{
		State:   state,
		VPToken: map[string][]string{"pid": {"eyJhbGciOiJFUzI1NiJ9.e30.sig~"}},
	})
	require.NoError(t, err)

	response, err := jwe.Encrypt(raw,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)
	return string(response)
}

func pendingSession(sessionID, state string, expiresAt int64) *cache.AuthorizationContext {
	return &cache.AuthorizationContext{
		SessionID:             sessionID,
		Status:                cache.SessionStatusPending,
		CreatedAt:             time.Now(),
		ExpiresAt:             expiresAt,
		ClientID:              "test-client",
		RedirectURI:           "https://client.example.com/callback",
		State:                 state,
		Scopes:                []string{"openid"},
		WalletFollowsRedirect: true,
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
		}}},
	}
}

// A wallet that posts after the presentation deadline is refused.
//
// GetOIDCRequestObject checks ExpiresAt when it SERVES the request object,
// which only bounds when a wallet may start. ProcessDirectPost did not
// check it at all, so a wallet that fetched a second before the deadline
// could post its response any time until the cache evicted the session -
// at least fifteen minutes. The timeout bounded the wrong half of the flow.
func TestProcessDirectPostRefusesAnExpiredSession(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	const sessionID = "expired-oidc-session"
	require.NoError(t, client.cacheService.AuthContext.Create(ctx,
		pendingSession(sessionID, sessionID, time.Now().Add(-time.Second).Unix())))

	response := encryptedVPResponse(t, client, sessionID, sessionID)

	_, err := client.ProcessDirectPost(ctx, &DirectPostRequest{Response: response})
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// ... and one that posts inside it is not, so the test above is a deadline
// test and not "direct post is broken".
func TestProcessDirectPostAcceptsASessionInsideTheDeadline(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	const sessionID = "live-oidc-session"
	require.NoError(t, client.cacheService.AuthContext.Create(ctx,
		pendingSession(sessionID, sessionID, time.Now().Add(10*time.Minute).Unix())))

	response := encryptedVPResponse(t, client, sessionID, sessionID)

	_, err := client.ProcessDirectPost(ctx, &DirectPostRequest{Response: response})
	assert.NotErrorIs(t, err, ErrSessionExpired)
}

// The standalone verification flow had no deadline check either: it
// processed an expired authorization context until the cache evicted it.
func TestVerificationDirectPostRefusesAnExpiredSession(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	const sessionID, state = "expired-verification-session", "expired-state"
	session := pendingSession(sessionID, state, time.Now().Add(-time.Second).Unix())
	session.EphemeralEncryptionKeyID = sessionID
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, session))

	response := encryptedVPResponse(t, client, sessionID, state)

	_, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: response})
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// A session with no deadline at all - every context created before
// presentation_timeout was read - must keep working, not be read as
// "expired at the epoch".
func TestAZeroDeadlineIsNotTreatedAsExpired(t *testing.T) {
	assert.False(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: 0}))
	assert.False(t, sessionExpired(nil))
	assert.True(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: time.Now().Add(-time.Second).Unix()}))
	assert.False(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: time.Now().Add(time.Minute).Unix()}))
}

// The deadline second itself is already past the deadline.
//
// isReusableAuthContext treats ExpiresAt <= now as expired. sessionExpired
// used >, so with timestamps truncated to seconds direct-post stayed open
// for the whole boundary second after the UI had given up on the session.
func TestTheExpiryBoundarySecondIsExpired(t *testing.T) {
	now := time.Now().Unix()

	assert.True(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: now}),
		"the deadline second must be expired, as isReusableAuthContext reads it")
	assert.True(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: now - 1}))
	assert.False(t, sessionExpired(&cache.AuthorizationContext{ExpiresAt: now + 1}))
}

// A resume past the deadline is not pending.
//
// UIResume checked the completed case and the request object cache, but
// never the session's own deadline - and the request object now outlives it
// by its own floor. So a reload past the deadline reissued the dead QR and
// minted a fresh DC API request_uri for a session the direct-post handlers
// would refuse.
func TestUIResumeRefusesAnExpiredSession(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	if client.cfg.Verifier.Inbound.OpenID4VP == nil {
		client.cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{}
	}
	client.cfg.Verifier.Inbound.OpenID4VP.PresentationTimeout = 1800

	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)
	require.NotEmpty(t, reply.SessionID)

	// Inside the deadline it resumes.
	resumed, err := client.UIResume(ctx, reply.SessionID)
	require.NoError(t, err)
	require.Equal(t, UIResumePending, resumed.Status)

	// Past it, it does not - while the request object is still cached, so
	// this cannot pass because the object happened to expire.
	session, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
	require.NoError(t, err)
	session.ExpiresAt = time.Now().Add(-time.Second).Unix()
	require.NoError(t, client.cacheService.AuthContext.Update(ctx, session))

	_, err = client.cacheService.RequestObject.GetErr(ctx, session.RequestObjectID)
	require.NoError(t, err, "the request object must still be cached for this test to mean anything")

	resumed, err = client.UIResume(ctx, reply.SessionID)
	require.NoError(t, err)
	assert.Equal(t, UIResumeExpired, resumed.Status)
}

// Confirming a credential display past the deadline cannot mint a code.
//
// This was the third place a code is issued and the last one with no
// deadline check, so a confirmation could issue one arbitrarily late -
// and MongoDB's retention, anchored to CreatedAt, could then evict the
// session while that code was still valid.
func TestConfirmCredentialDisplayRefusesAnExpiredSession(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	const sessionID = "expired-confirm-session"
	session := pendingSession(sessionID, sessionID, time.Now().Add(-time.Second).Unix())
	session.Status = cache.SessionStatusAwaitingPresentation
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, session))

	_, err := client.ConfirmCredentialDisplay(ctx, &ConfirmCredentialDisplayRequest{
		SessionID: sessionID,
		Confirmed: true,
	})
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// The credential display gets a window of its own.
//
// Reusing the presentation deadline for it meant a wallet that answered
// just before the deadline left the user no time to read the display at
// all - presentation_timeout is documented as the time the WALLET has, and
// confirming is a different step by a different party.
func TestTheCredentialDisplayGetsItsOwnWindow(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)
	if client.cfg.Verifier.Inbound.OpenID4VP == nil {
		client.cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{}
	}
	client.cfg.Verifier.Inbound.OpenID4VP.PresentationTimeout = 600

	// A session near its presentation deadline, whose wallet response
	// arrives right now. A minute rather than a second: the assertion is
	// that the window is RESET to 600s, which a minute proves just as well,
	// and a second could elapse while this test builds the JWE on a loaded
	// runner.
	const sessionID = "display-window-session"
	session := pendingSession(sessionID, sessionID, time.Now().Add(time.Minute).Unix())
	session.ShowCredentialDetails = true
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, session))

	response := encryptedVPResponse(t, client, sessionID, sessionID)
	_, err := client.ProcessDirectPost(ctx, &DirectPostRequest{Response: response})
	require.NoError(t, err)

	stored, err := client.cacheService.AuthContext.GetByID(ctx, sessionID)
	require.NoError(t, err)
	require.Equal(t, cache.SessionStatusAwaitingPresentation, stored.Status)

	// A fresh 600s to read and confirm, not the one second that was left.
	assert.InDelta(t, time.Now().Add(600*time.Second).Unix(), stored.ExpiresAt, 5,
		"the user inherited whatever was left of the wallet's deadline")
	assert.Greater(t, stored.ExpiresAt, time.Now().Add(5*time.Minute).Unix(),
		"the deadline still looks like the wallet's remaining time")
	assert.False(t, sessionExpired(stored))

	// ... and confirming now works, where before it was refused outright.
	_, err = client.ConfirmCredentialDisplay(ctx, &ConfirmCredentialDisplayRequest{
		SessionID: sessionID,
		Confirmed: true,
	})
	assert.NotErrorIs(t, err, ErrSessionExpired)
}

// One boundary across the whole flow: the request-object endpoint must not
// serve a request during the second the direct-post handlers would refuse
// its response.
func TestTheRequestObjectEndpointSharesTheExpiryBoundary(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	const sessionID = "boundary-session"
	require.NoError(t, client.cacheService.AuthContext.Create(ctx,
		pendingSession(sessionID, sessionID, time.Now().Unix())))

	_, err := client.GetOIDCRequestObject(ctx, &GetRequestObjectRequest{SessionID: sessionID})
	assert.ErrorIs(t, err, ErrSessionExpired,
		"a request object was served during the second its response would be refused")
}
