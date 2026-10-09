package apiv1

import (
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The authorization session's deadline is openid4vp.presentation_timeout.
//
// It used to be oidc_provider.code_duration - the lifetime of the
// authorization CODE, a different clock that starts later, once the
// presentation has already succeeded. Sharing one key meant lengthening the
// code's life silently lengthened the presentation window, and
// presentation_timeout, the key named for this, was read nowhere at all
// (SUNET/vc#756).
func TestAuthorizeSessionExpiresAfterThePresentationTimeout(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	if client.cfg.Verifier.Inbound.OpenID4VP == nil {
		client.cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{}
	}
	client.cfg.Verifier.Inbound.OpenID4VP.PresentationTimeout = 1800
	// Deliberately different, and deliberately shorter: if the session
	// deadline still came from code_duration this test would read 60.
	client.cfg.Verifier.Outbound.OIDCProvider.CodeDuration = 60
	client.AddPresentationTemplateForTesting(createSimplePresentationTemplate(t, []string{"openid", "profile"}))

	require.NoError(t, mockDB.Clients.Create(ctx, &db.Client{
		ClientID:      "test-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid", "profile"},
	}))

	before := time.Now()
	resp, err := client.Authorize(ctx, &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "test-client",
		RedirectURI:  "https://example.com/callback",
		Scope:        strings.Join([]string{"openid", "profile"}, " "),
		State:        "state",
		Nonce:        "nonce",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	session, err := client.cacheService.AuthContext.GetByID(ctx, resp.SessionID)
	require.NoError(t, err)
	require.NotNil(t, session)

	// 1800s out, not 60s.
	assert.InDelta(t, before.Add(1800*time.Second).Unix(), session.ExpiresAt, 5,
		"the session deadline is not the presentation timeout")
	assert.Greater(t, session.ExpiresAt, before.Add(10*time.Minute).Unix(),
		"the session deadline still looks like code_duration")
}

// The standalone verification session gets a deadline of its own.
//
// It was created with ExpiresAt: 0, and isSessionActive reads 0 as "never
// expires" - so the session had no deadline and lived until the auth-context
// cache evicted it. openid4vp.presentation_timeout, the key written for
// exactly this flow, was read nowhere (SUNET/vc#756).
func TestUIInteractionSessionHasAPresentationDeadline(t *testing.T) {
	ctx := t.Context()

	client := newSigningTestClient(t)
	if client.cfg.Verifier.Inbound.OpenID4VP == nil {
		client.cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{}
	}
	client.cfg.Verifier.Inbound.OpenID4VP.PresentationTimeout = 1800

	before := time.Now()
	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)
	require.NotEmpty(t, reply.SessionID)

	session, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotZero(t, session.ExpiresAt, "a zero ExpiresAt is read as 'never expires'")
	assert.InDelta(t, before.Add(1800*time.Second).Unix(), session.ExpiresAt, 5)
}
