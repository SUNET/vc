package apiv1

import (
	"context"
	stdcrypto "crypto"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/lestrrat-go/jwx/v3/jwk"
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
	if err := d.failureFor(query); err != nil {
		return nil, err
	}
	return d.AuthContextStore.Get(ctx, query)
}

// Both reads, because which one a handler uses is its business: a reader
// takes a snapshot and a read-modify-Update caller takes the document,
// and an outage stops either.
func (d *downAuthContextStore) GetSnapshot(ctx context.Context, query *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	if err := d.failureFor(query); err != nil {
		return nil, err
	}
	return d.AuthContextStore.GetSnapshot(ctx, query)
}

func (d *downAuthContextStore) failureFor(query *cache.AuthorizationContext) error {
	if query == nil {
		return nil
	}
	if d.failAuthSession && query.AuthSession != "" {
		return errStoreDown
	}
	if d.failIssuerState && query.IssuerState != "" {
		return errStoreDown
	}
	return nil
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

// Two wallets scanning one prepared issuance both build a request object
// before either has claimed the handle - that ordering is deliberate, so
// a failure cannot destroy an issuance nothing re-prepares. It means the
// ephemeral encryption key must not be provisioned under an id they
// share: EphemeralEncryptionKey is a Get-then-Set, so both would miss,
// both would generate, and the private key left in the cache would be
// whichever Set landed last - which need not be the public key the
// WINNING wallet was handed. Its encrypted presentation would then be
// undecryptable, and the exchange would be lost after the Holder had
// already consented.
//
// Each attempt therefore mints its own key id and the winner's is
// persisted by the atomic claim, so the id stored is always the one whose
// request object was actually returned.
func TestIssuerInitiated_ConcurrentResumesDoNotShareAnEncryptionKey(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	prepared, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		IssuerState: issuerState,
	})
	require.NoError(t, err)
	preparedKeyID := prepared.EphemeralEncryptionKeyID
	require.NotEmpty(t, preparedKeyID)

	const attempts = 4
	var (
		mu     sync.Mutex
		opened []*AuthorizationChallengeError
		wg     sync.WaitGroup
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := initialChallenge(t)
			req.Scope = ""
			req.IssuerState = issuerState
			_, err := client.OAuthAuthorizationChallenge(t.Context(), req)

			var challengeErr *AuthorizationChallengeError
			if errors.As(err, &challengeErr) {
				mu.Lock()
				opened = append(opened, challengeErr)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	require.Len(t, opened, 1, "a one-shot handle yields exactly one exchange")
	winner := opened[0]

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: winner.AuthSession,
	})
	require.NoError(t, err)
	assert.NotEqual(t, preparedKeyID, authCtx.EphemeralEncryptionKeyID,
		"the attempt's own key id must replace the one every attempt shared")

	// The decisive assertion: the private key the exchange will decrypt
	// with is the pair of the public key this wallet was actually handed.
	advertised := advertisedEncryptionKey(t, winner.OpenID4VPRequest)
	stored, ok := client.cacheService.EphemeralEncryptionKey.Get(t.Context(), authCtx.EphemeralEncryptionKeyID)
	require.True(t, ok, "the stored key must be the one the winning request object named")

	storedPublic, err := stored.PublicKey()
	require.NoError(t, err)
	storedThumb, err := storedPublic.Thumbprint(stdcrypto.SHA256)
	require.NoError(t, err)
	advertisedThumb, err := advertised.Thumbprint(stdcrypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, storedThumb, advertisedThumb,
		"the response is encrypted to the advertised key, so the stored private half must match it")
}

// advertisedEncryptionKey reads the key a signed Interactive
// Authorization request object offered in client_metadata.jwks.
func advertisedEncryptionKey(t *testing.T, raw json.RawMessage) jwk.Key {
	t.Helper()

	var signed struct {
		Request string `json:"request"`
	}
	require.NoError(t, json.Unmarshal(raw, &signed))
	require.NotEmpty(t, signed.Request)

	claims := unsafeJWTClaims(t, signed.Request)
	metadata, ok := claims["client_metadata"].(map[string]any)
	require.True(t, ok, "the request must carry client_metadata")
	jwks, ok := metadata["jwks"].(map[string]any)
	require.True(t, ok, "the request must advertise an encryption key")

	encoded, err := json.Marshal(jwks)
	require.NoError(t, err)
	set, err := jwk.Parse(encoded)
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())
	key, ok := set.Key(0)
	require.True(t, ok)
	return key
}
