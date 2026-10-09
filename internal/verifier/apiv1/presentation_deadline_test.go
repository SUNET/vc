package apiv1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
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
