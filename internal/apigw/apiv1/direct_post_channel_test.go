package apiv1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/cache"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptedToEphemeralKey builds the JWE the direct_post endpoint expects:
// encrypted to the context's ephemeral key, with that key's kid in the
// header, which is the only thing that endpoint uses to find the context.
func encryptedToEphemeralKey(t *testing.T, client *Client, kid string, payload any) string {
	t.Helper()

	_, publicJWK, err := client.EphemeralEncryptionKey(t.Context(), kid)
	require.NoError(t, err)

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(body,
		jwe.WithKey(jwa.ECDH_ES(), publicJWK),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)
	return string(encrypted)
}

// An Interactive Authorization exchange must be answerable at the
// Authorization Challenge Endpoint and nowhere else.
//
// The challenge endpoint verifies holder binding before accepting a
// presentation. /verification/direct_post does not, and it finds a context
// by EphemeralEncryptionKeyID - which an IA context also has, and whose
// kid the wallet was handed in the request's client_metadata. Clearing
// auth_session does not close that door: it removes only the auth_session
// index, and the attack is available precisely afterwards.
//
// So without the marker a wallet could complete its own challenge
// honestly, then post a copied credential with a self-signed key binding
// proof here, overwrite VerifiedClaims on the context its own
// authorization code belongs to, and redeem that code for a credential
// built from someone else's claims.
func TestVerificationDirectPost_RefusesAnInteractiveAuthorizationContext(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	require.True(t, authCtx.InteractiveAuthorization,
		"an exchange opened by the challenge endpoint must be marked as answerable there")
	require.NotEmpty(t, authCtx.EphemeralEncryptionKeyID)

	// The handle is consumed, which is when the attack is available - and
	// the marker has to survive that, like AuthSessionDPoPThumbprint does.
	claimed, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)
	require.True(t, claimed.InteractiveAuthorization,
		"the marker must survive the auth_session being consumed")

	response := encryptedToEphemeralKey(t, client, authCtx.EphemeralEncryptionKeyID,
		map[string]any{"state": authCtx.State, "vp_token": map[string]any{"pid": "forged"}})

	_, err = client.VerificationDirectPost(t.Context(), &VerificationDirectPostRequest{Response: response})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "authorization challenge endpoint",
		"the refusal must name the channel, not fail for some unrelated reason")

	// And nothing was written. Asserted on the STORE: an endpoint that
	// refused after persisting would satisfy the error check above while
	// the overwrite had already happened.
	after, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		EphemeralEncryptionKeyID: authCtx.EphemeralEncryptionKeyID,
	})
	require.NoError(t, err, "the context itself is untouched")
	assert.Nil(t, after.VerifiedClaims,
		"a presentation refused for being on the wrong channel must not have overwritten the claims")
}

// A context opened BEFORE the marker existed must be refused too.
//
// The marker is new and the contexts are persisted: after an upgrade the
// store still holds Interactive Authorization contexts written by the
// previous version, whose documents have no interactive_authorization
// member at all. That decodes as false, so a guard reading only the
// marker would wave through exactly the exchanges it was added to stop,
// for as long as those contexts live.
//
// AuthSessionDPoPThumbprint is the durable second signal: the challenge
// endpoint refuses a request carrying no DPoP proof BEFORE it creates a
// context, so every IA context ever written has one, and no other path
// sets it.
func TestVerificationDirectPost_RefusesALegacyInteractiveAuthorizationContext(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	require.NotEmpty(t, authCtx.AuthSessionDPoPThumbprint,
		"the premise: an IA context always carries the thumbprint, so a legacy one does too")

	// What an upgrade finds in the store: the exchange, without the field
	// the new version writes.
	authCtx.InteractiveAuthorization = false
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), authCtx))

	response := encryptedToEphemeralKey(t, client, authCtx.EphemeralEncryptionKeyID,
		map[string]any{"state": authCtx.State, "vp_token": map[string]any{"pid": "forged"}})

	_, err = client.VerificationDirectPost(t.Context(), &VerificationDirectPostRequest{Response: response})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "authorization challenge endpoint",
		"a context opened before the marker existed is still an IA context")
}

// The browser-mediated flow is unaffected: its contexts carry no marker
// and still reach the pipeline. Without this, "refuse everything" would
// pass the test above.
func TestVerificationDirectPost_StillAcceptsABrowserContext(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	// The same context with BOTH Interactive Authorization markers
	// removed - a browser-flow context in every other respect, so the only
	// difference under test is the one being tested. The thumbprint has to
	// go too: a browser context never carries one, and leaving it would
	// make this test assert that the guard below does not exist.
	authCtx.InteractiveAuthorization = false
	authCtx.AuthSessionDPoPThumbprint = ""
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), authCtx))

	response := encryptedToEphemeralKey(t, client, authCtx.EphemeralEncryptionKeyID,
		map[string]any{"state": authCtx.State, "vp_token": map[string]any{"pid": "forged"}})

	_, err = client.VerificationDirectPost(t.Context(), &VerificationDirectPostRequest{Response: response})
	require.Error(t, err, "the fixture carries no real presentation, so this still fails")
	assert.NotContains(t, strings.ToLower(err.Error()), "authorization challenge endpoint",
		"a browser context must get past the channel check and fail on the presentation instead")
}

// A resumed issuer_state is an Interactive Authorization exchange too,
// and has to be marked as one.
//
// The prepared issuance is not yet an exchange, so the context the
// preparation wrote carries no marker - and the resume copies that
// context. The exchange it opens hands the wallet an ephemeral key id in
// a request answered at the challenge endpoint, and that key id is what
// /verification/direct_post resolves a context by. Without the marker, an
// issuer-initiated flow could be answered at the endpoint that verifies
// neither the holder binding nor the credential's validity window, and
// have its presentation-sourced claims overwritten before the wallet
// redeemed its own code.
//
// The resume path also ROTATES the key id, so the test reads the one the
// opened exchange actually recorded rather than the prepared one.
func TestVerificationDirectPost_RefusesAResumedIssuerStateExchange(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	req := initialChallenge(t)
	req.Scope = ""
	req.IssuerState = issuerState
	opened := challengeErr(t, client, req)
	require.NotEmpty(t, opened.AuthSession)

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	require.True(t, authCtx.InteractiveAuthorization,
		"a resumed issuer_state opens an exchange answerable at the challenge endpoint")
	require.NotEmpty(t, authCtx.EphemeralEncryptionKeyID)

	// Consumed, which is when the other endpoint becomes reachable.
	claimed, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)
	require.True(t, claimed.InteractiveAuthorization, "the marker must survive the claim")

	response := encryptedToEphemeralKey(t, client, authCtx.EphemeralEncryptionKeyID,
		map[string]any{"state": authCtx.State, "vp_token": map[string]any{"pid": "forged"}})

	_, err = client.VerificationDirectPost(t.Context(), &VerificationDirectPostRequest{Response: response})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "authorization challenge endpoint")

	after, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		EphemeralEncryptionKeyID: authCtx.EphemeralEncryptionKeyID,
	})
	require.NoError(t, err)
	assert.Nil(t, after.VerifiedClaims,
		"a presentation refused for being on the wrong channel must not have overwritten the claims")
}
