package apiv1

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errStoreDown is what a MongoDB outage looks like from the handler: not
// "this handle does not exist", but "nothing can be read right now".
var errStoreDown = errors.New("connection reset by peer")

// downAuthContextStore fails the lookup of one kind of handle and behaves
// normally otherwise.
type downAuthContextStore struct {
	cache.AuthContextStore
	failAuthSession bool
	failIssuerState bool
}

func (d *downAuthContextStore) Get(ctx context.Context, query *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	if query != nil {
		if d.failAuthSession && query.AuthSession != "" {
			return nil, errStoreDown
		}
		if d.failIssuerState && query.IssuerState != "" {
			return nil, errStoreDown
		}
	}
	return d.AuthContextStore.Get(ctx, query)
}

// A store that could not answer has not said the handle is invalid, and
// invalid_grant is a terminal answer: it tells the wallet to throw the
// exchange away and start over. During an outage that is the request that
// will fail next, so a transient fault turned into a destroyed exchange.
//
// Unknown and expired stay one answer - that is what keeps the endpoint
// from being an oracle for which handles exist - but "the store is down"
// is not one of them.
func TestChallenge_StoreOutageIsNotInvalidGrant(t *testing.T) {
	t.Run("auth_session", func(t *testing.T) {
		client := newChallengeClient(t)
		client.cacheService.AuthContext = &downAuthContextStore{
			AuthContextStore: client.cacheService.AuthContext,
			failAuthSession:  true,
		}

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, strings.Repeat("a", 43), "an-encrypted-response"))

		assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode,
			"a store that could not be read must not be reported as an invalid auth_session")
		assert.Equal(t, 500, oauthErr.HTTPStatus)
	})

	t.Run("issuer_state", func(t *testing.T) {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())
		client.cacheService.AuthContext = &downAuthContextStore{
			AuthContextStore: client.cacheService.AuthContext,
			failIssuerState:  true,
		}

		req := initialChallenge(t)
		req.Scope = ""
		req.IssuerState = issuerState

		oauthErr := oauthErrFromChallenge(t, client, req)
		assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode,
			"a store that could not be read must not be reported as a spent issuer_state")
		assert.Equal(t, 500, oauthErr.HTTPStatus)
	})
}

// updateRefusingStore accepts everything but Update.
//
// Resuming a prepared issuance used to claim the one-shot issuer_state and
// then write the resumed exchange with a separate Update. This store makes
// that second write fail, which is the window the two-call shape left
// open.
type updateRefusingStore struct {
	cache.AuthContextStore
}

func (u *updateRefusingStore) Update(ctx context.Context, doc *cache.AuthorizationContext) error {
	return errStoreDown
}

// Claiming the handle and recording the exchange are one store operation,
// so there is no state in which the issuance has been consumed and no
// resumable exchange exists.
//
// A prepared issuance is the product of someone authenticating at a portal
// and choosing what to be issued, and nothing re-prepares it. Destroying
// one over a write that failed on our side is the outcome the whole
// ordering of this handler exists to prevent, and the separate Update was
// the one step that could still do it.
func TestIssuerInitiated_ResumeSurvivesAFailingUpdate(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())
	client.cacheService.AuthContext = &updateRefusingStore{AuthContextStore: client.cacheService.AuthContext}

	req := initialChallenge(t)
	req.Scope = ""
	req.IssuerState = issuerState

	opened := challengeErr(t, client, req)
	assert.Equal(t, 403, opened.HTTPStatus)
	require.NotEmpty(t, opened.AuthSession,
		"the resumed exchange must exist even though a separate Update would have failed")

	// And the exchange really is there to be continued.
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	assert.Equal(t, "wallet-1", authCtx.WalletClientID)
	assert.NotEmpty(t, authCtx.AuthSessionDPoPThumbprint)
	assert.Equal(t, []string{challengeScope}, authCtx.Scopes)
	require.NotNil(t, authCtx.DCQLQuery, "the wallet was told what to present, so the exchange must remember it")

	// The handle is spent, exactly as it is on the healthy path: one
	// operation either does both or neither.
	spent, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		IssuerState: issuerState,
	})
	require.ErrorIs(t, err, cache.ErrNoDocuments)
	assert.Nil(t, spent)
}
