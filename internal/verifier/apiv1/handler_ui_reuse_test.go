package apiv1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cross-device reload replays /ui/interaction with the same session id
// hint (out of sessionStorage or the gin cookie). The server must return
// the SAME session_id and the SAME authorization_request that the wallet
// is already scanning, or the wallet's direct_post lands on an orphaned
// authorization context whose SSE listener no longer exists.
func TestUIInteraction_ReuseInFlightSession(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)

	dcql := createTestDCQLForVP(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: dcql})
	require.NoError(t, err)
	require.NotEmpty(t, first.SessionID)
	require.NotEmpty(t, first.AuthorizationRequest)

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.Equal(t, first.SessionID, second.SessionID, "reload must reuse the same session_id")
	assert.Equal(t, first.AuthorizationRequest, second.AuthorizationRequest, "reload must reuse the same request_uri so the wallet's QR still resolves")
	assert.Equal(t, first.QRCode, second.QRCode, "same request_uri must render an identical QR")
}

// The wallet has already delivered its direct_post - a Token is on the
// context. A reload here is not a resume attempt; it must start a fresh
// interaction rather than serving a claimed session back to the browser.
func TestUIInteraction_NoReuseAfterCompletion(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	dcql := createTestDCQLForVP(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: dcql})
	require.NoError(t, err)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	authCtx.Token = &cache.Token{AccessToken: "opaque", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, client.cacheService.AuthContext.Update(ctx, authCtx))

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID, "consumed session must not be handed back")
}

// A forfeited authorization context is closed for reuse regardless of
// whether a wallet ever engaged with it.
func TestUIInteraction_NoReuseAfterForfeit(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	authCtx.Forfeited = true
	require.NoError(t, client.cacheService.AuthContext.Update(ctx, authCtx))

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID, "forfeited session must not be handed back")
}

// An expired ExpiresAt in the past retires the context from reuse.
// (ExpiresAt == 0 is treated as "no explicit expiry" by the reuse check;
// only strictly-positive-and-in-the-past values retire the context.)
func TestUIInteraction_NoReuseAfterExpiry(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	authCtx.ExpiresAt = time.Now().Add(-1 * time.Second).Unix()
	require.NoError(t, client.cacheService.AuthContext.Update(ctx, authCtx))

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID, "expired session must not be handed back")
}

// Changing the requested DCQL cannot mean "reuse": the wallet is holding a
// request_uri whose DCQL says X, but the browser now wants Y. Handing back
// the old context would silently ignore Y; minting a fresh one obeys it,
// and the old context times out on its own.
func TestUIInteraction_NoReuseOnDCQLChange(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)

	otherDCQL := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:     "other_credential",
				Format: "vc+sd-jwt",
				Meta:   openid4vp.MetaQuery{VCTValues: []string{"https://example.com/credential/other"}},
			},
		},
	}
	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: otherDCQL,
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID, "changed DCQL must not reuse the old session")

	oldStill, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	require.NotNil(t, oldStill, "old context must still be around for the wallet the user already scanned")
}

// The RequestObject cache TTL is shorter than the AuthorizationContext
// TTL, so an old-enough reload can find the auth context but not the
// request object. Reuse must decline: reconstructing the request object
// from scratch would race the wallet still holding the original URI.
func TestUIInteraction_NoReuseWhenRequestObjectGone(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)

	authCtx, err := client.cacheService.AuthContext.GetByID(ctx, first.SessionID)
	require.NoError(t, err)
	client.openid4vp.RequestObjectCache.Delete(authCtx.RequestObjectID)

	second, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: first.SessionID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.SessionID, second.SessionID, "missing request object must force a fresh session")
}

// An unknown SessionID hint is not an error - it is a stale value in the
// caller's sessionStorage. Fall back to fresh, do not 500.
func TestUIInteraction_UnknownSessionIDMintsFresh(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
		SessionID: "session-that-never-existed",
	})
	require.NoError(t, err)
	require.NotEmpty(t, reply.SessionID)
	assert.NotEqual(t, "session-that-never-existed", reply.SessionID)
}

// Direct sanity check for the JSON-equality helper: a value that only
// serialises differently must NOT count as equal, and a nil vs empty is
// handled deterministically (both nil is equal; one nil, one non-nil is
// not).
func TestSameDCQLQuery(t *testing.T) {
	a := createTestDCQLForVP(t)
	b := createTestDCQLForVP(t)
	assert.True(t, sameDCQLQuery(a, b), "structurally-identical DCQL must compare equal")

	b.Credentials[0].ID = "different"
	assert.False(t, sameDCQLQuery(a, b), "different DCQL must not compare equal")

	assert.True(t, sameDCQLQuery(nil, nil), "two nils are equal")
	assert.False(t, sameDCQLQuery(nil, a), "nil vs non-nil is not equal")

	// Belt-and-braces that the round-trip is stable: encoding and decoding
	// a stored request object's DCQL must still compare equal to the
	// original, or reload traffic will forever miss the cache.
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var round openid4vp.DCQL
	require.NoError(t, json.Unmarshal(raw, &round))
	assert.True(t, sameDCQLQuery(a, &round), "json round-trip must round-trip")
}

// isReusableAuthContext gates every reuse decision. Cover its explicit
// cases so a future refactor cannot silently widen or narrow the contract.
func TestIsReusableAuthContext(t *testing.T) {
	fresh := &cache.AuthorizationContext{ExpiresAt: 0}
	assert.True(t, isReusableAuthContext(fresh), "unclaimed, unforfeited, unexpired context is reusable")

	assert.False(t, isReusableAuthContext(&cache.AuthorizationContext{Forfeited: true}), "forfeited")
	assert.False(t, isReusableAuthContext(&cache.AuthorizationContext{Code: "issued"}), "code issued")
	assert.False(t, isReusableAuthContext(&cache.AuthorizationContext{Token: &cache.Token{AccessToken: "t", ExpiresAt: 1}}), "token issued")
	assert.False(t, isReusableAuthContext(&cache.AuthorizationContext{ExpiresAt: time.Now().Add(-time.Minute).Unix()}), "expired")
	assert.True(t, isReusableAuthContext(&cache.AuthorizationContext{ExpiresAt: time.Now().Add(time.Minute).Unix()}), "future expiry is fine")
}

// A tab that opens /ui/interaction without a hint is the fresh-visit
// case: no session_id in the body or cookie, so apiv1 must mint one and
// return it to the client.
func TestUIInteraction_NoHintMintsFresh(t *testing.T) {
	ctx := context.Background()

	client := newSigningTestClient(t)
	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)
	require.NotEmpty(t, reply.SessionID)
	require.NotEmpty(t, reply.AuthorizationRequest)
}
