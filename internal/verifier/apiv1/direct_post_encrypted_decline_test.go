package apiv1

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/cache"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The encrypted-decline path, end to end: a real JWE through
// VerificationDirectPost with only Response set, which is what a wallet using
// direct_post.jwt sends (OpenID4VP 1.0 5.6 - "Both successful and error
// responses SHOULD be returned using the supplied Response Mode").
//
// Its sibling in direct_post_decline_test.go calls directPostError directly,
// so it never builds or decrypts an envelope and would keep passing with the
// encrypted-error branch in VerificationDirectPost deleted. This one does not:
// delete that branch and the payload reaches the presentation parse instead,
// which has no vp_token to find.
func TestVerificationDirectPostRecordsAnEncryptedDecline(t *testing.T) {
	ctx := context.Background()

	// In this flow state IS the session id, and the ephemeral key is cached
	// under the same value, so the kid the wallet echoes back equals the
	// state inside the JWE.
	const state = "declining-session"

	client, _ := declineClient(t, state)

	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, state)
	require.NoError(t, err)

	raw, err := json.Marshal(map[string]string{
		"error":             "access_denied",
		"error_description": "the user declined to present",
		"state":             state,
	})
	require.NoError(t, err)

	response, err := jwe.Encrypt(raw,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	reply, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(response)})
	require.NoError(t, err)
	require.NotNil(t, reply)

	// The discriminator the Digital Credentials API page reads: that page
	// forwards the wallet's response itself and never opens SSE, so an empty
	// 200 would have it report a verified presentation for a refusal.
	assert.True(t, reply.Declined, "an encrypted decline must say so in the body")
	assert.Equal(t, "access_denied", reply.Error)
	assert.Equal(t, "the user declined to present", reply.ErrorDescription)

	stored, err := client.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: state})
	require.NoError(t, err)
	assert.Equal(t, cache.SessionStatusError, stored.Status, "the refusal must be persisted, not only answered")
	assert.Equal(t, "access_denied", stored.Error)
	assert.Equal(t, "the user declined to present", stored.ErrorDescription)
}
