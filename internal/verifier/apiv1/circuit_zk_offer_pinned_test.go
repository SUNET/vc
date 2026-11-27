package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// offeredCircuit is what the configuration below offers, and what every
// session opened under it must record.
const offeredCircuit = "urn:circuits:longfellow:nym_auth:v1"

// withZkpReqOffer configures a verifier that offers one circuit.
func withZkpReqOffer(t *testing.T, client *Client) {
	t.Helper()
	client.cfg.Verifier.PreferredVPFormats = &openid4vp.VPFormatsSupported{
		ZkpReq: &openid4vp.ZkpReqFormat{SystemIDValues: []string{offeredCircuit}},
	}
}

// A session records the zkp_req offer its request object carries, on every
// path that opens one.
//
// Through the real handlers and the real store, because the recording is
// the point: circuitZkRequestFor prefers a session's own offer and falls
// back to the configuration when there is none, so a path that never
// records one silently keeps the behaviour this change exists to replace -
// and every unit test of circuitZkRequestFor still passes.
func TestASessionRecordsTheZkpReqOfferItWasOpenedWith(t *testing.T) {
	t.Run("the OIDC relying-party flow", func(t *testing.T) {
		ctx := t.Context()

		client, mockDB := CreateTestClientWithMock(t, nil)
		client.cfg.Verifier.PublicURL = "https://verifier.example.com"
		withZkpReqOffer(t, client)
		client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid", "profile"}))

		require.NoError(t, mockDB.Clients.Create(ctx, &db.Client{
			ClientID:      "test-client",
			RedirectURIs:  []string{"https://example.com/callback"},
			ResponseTypes: []string{"code"},
			AllowedScopes: []string{"openid", "profile"},
		}))

		resp, err := client.Authorize(ctx, &AuthorizeRequest{
			ResponseType:        "code",
			ClientID:            "test-client",
			RedirectURI:         "https://example.com/callback",
			Scope:               strings.Join([]string{"openid", "profile"}, " "),
			State:               "state",
			Nonce:               "nonce",
			CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			CodeChallengeMethod: "S256",
		})
		require.NoError(t, err)

		session, err := client.cacheService.AuthContext.GetByID(ctx, resp.SessionID)
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, []string{offeredCircuit}, session.OfferedZkpReqSystemIDs)
	})

	t.Run("the standalone verification flow", func(t *testing.T) {
		ctx := t.Context()

		client, _ := CreateTestClientWithMock(t, nil)
		client.cfg.Verifier.PublicURL = "https://verifier.example.com"
		withZkpReqOffer(t, client)

		reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
		require.NoError(t, err)
		require.NotNil(t, reply)

		session, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, []string{offeredCircuit}, session.OfferedZkpReqSystemIDs)
	})
}

// A verifier that offers no zkp_req records nothing, which is what sends
// verification to the configuration rather than to an offer of nothing.
//
// The distinction matters because an empty recorded offer refuses every
// response: a deployment with no zkp_req configured at all must not look
// like one that deliberately offered an empty list.
func TestASessionWithNoZkpReqOfferRecordsNothing(t *testing.T) {
	ctx := t.Context()

	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.PreferredVPFormats = &openid4vp.VPFormatsSupported{}

	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)

	session, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Nil(t, session.OfferedZkpReqSystemIDs)

	// And the fallback that absence selects is the configuration.
	var _ *model.Cfg = client.cfg
	request := client.circuitZkRequestFor(session, openid4vp.CredentialQuery{ID: "q"})
	assert.Empty(t, request.OfferedSystemIDs)
}
