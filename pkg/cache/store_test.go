package cache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryStoreImplementsInterface verifies the MemoryStore satisfies AuthContextStore.
func TestMemoryStoreImplementsInterface(t *testing.T) {
	var store AuthContextStore = NewMemoryStore(5 * time.Minute)
	require.NotNil(t, store)
}

// TestInterfaceContract_Memory runs the shared contract tests against the MemoryStore.
func TestInterfaceContract_Memory(t *testing.T) {
	store := NewMemoryStore(5 * time.Minute)
	runAuthContextStoreContractTests(t, store)
}

// runAuthContextStoreContractTests tests the contract that all AuthContextStore
// implementations must satisfy. This enables reuse for both memory and mongo backends.
func runAuthContextStoreContractTests(t *testing.T, store AuthContextStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("SaveAndGetByID", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID:  "contract-session-1",
			RequestURI: "https://example.com/req1",
			Code:       "code-1",
			State:      "state-1",
		}
		require.NoError(t, store.Save(ctx, doc))

		result, err := store.GetByID(ctx, "contract-session-1")
		require.NoError(t, err)
		assert.Equal(t, "contract-session-1", result.SessionID)
		assert.Equal(t, "code-1", result.Code)
	})

	t.Run("GetByCode", func(t *testing.T) {
		result, err := store.GetByAuthorizationCode(ctx, "code-1")
		require.NoError(t, err)
		assert.Equal(t, "contract-session-1", result.SessionID)
	})

	t.Run("GetByQueryFields", func(t *testing.T) {
		result, err := store.Get(ctx, &AuthorizationContext{State: "state-1"})
		require.NoError(t, err)
		assert.Equal(t, "contract-session-1", result.SessionID)
	})

	t.Run("Update", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID:  "contract-session-1",
			RequestURI: "https://example.com/req1",
			Code:       "code-1-updated",
			State:      "state-1",
		}
		require.NoError(t, store.Update(ctx, doc))

		result, err := store.GetByID(ctx, "contract-session-1")
		require.NoError(t, err)
		assert.Equal(t, "code-1-updated", result.Code)
	})

	t.Run("Consent", func(t *testing.T) {
		require.NoError(t, store.Consent(ctx, &AuthorizationContext{RequestURI: "https://example.com/req1"}))

		result, err := store.GetByID(ctx, "contract-session-1")
		require.NoError(t, err)
		assert.True(t, result.Consent)
	})

	t.Run("AddToken", func(t *testing.T) {
		token := &Token{AccessToken: "contract-access-token", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		require.NoError(t, store.AddToken(ctx, "code-1-updated", token))

		result, err := store.GetByAccessToken(ctx, "contract-access-token")
		require.NoError(t, err)
		assert.Equal(t, "contract-session-1", result.SessionID)
	})

	t.Run("GetWithAccessToken", func(t *testing.T) {
		result, err := store.GetWithAccessToken(ctx, "contract-access-token")
		require.NoError(t, err)
		assert.Equal(t, "contract-session-1", result.SessionID)
	})

	t.Run("SetAuthenticSource", func(t *testing.T) {
		require.NoError(t, store.SetAuthenticSource(ctx, &AuthorizationContext{SessionID: "contract-session-1"}, "test-source"))

		result, err := store.GetByID(ctx, "contract-session-1")
		require.NoError(t, err)
		assert.Equal(t, "test-source", result.AuthenticSource)
	})

	t.Run("ForfeitAuthorizationCode", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID: "contract-forfeit-session",
			Code:      "forfeit-code",
		}
		require.NoError(t, store.Save(ctx, doc))

		result, err := store.ForfeitAuthorizationCode(ctx, &AuthorizationContext{Code: "forfeit-code"})
		require.NoError(t, err)
		assert.True(t, result.Forfeited)

		// Second forfeit should fail
		_, err = store.ForfeitAuthorizationCode(ctx, &AuthorizationContext{Code: "forfeit-code"})
		assert.Error(t, err)
	})

	t.Run("MarkCodeAsForfeited", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID: "contract-mark-session",
			Code:      "mark-code",
		}
		require.NoError(t, store.Save(ctx, doc))

		require.NoError(t, store.MarkCodeAsForfeited(ctx, "contract-mark-session"))

		result, err := store.GetByID(ctx, "contract-mark-session")
		require.NoError(t, err)
		assert.True(t, result.Forfeited)
	})

	t.Run("RedeemPreAuthorizedCode", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID: "contract-preauth-session",
			Code:      "contract-preauth-code",
			Scopes:    []string{"openid"},
		}
		require.NoError(t, store.Save(ctx, doc))

		// First client redeems
		result, err := store.RedeemPreAuthorizedCode(ctx, "contract-preauth-code", "tp-1")
		require.NoError(t, err)
		assert.Contains(t, result.RedeemedBy, "tp-1")

		// Second client redeems
		result, err = store.RedeemPreAuthorizedCode(ctx, "contract-preauth-code", "tp-2")
		require.NoError(t, err)
		assert.Contains(t, result.RedeemedBy, "tp-1")
		assert.Contains(t, result.RedeemedBy, "tp-2")

		// Same client rejected
		_, err = store.RedeemPreAuthorizedCode(ctx, "contract-preauth-code", "tp-1")
		assert.Error(t, err)
	})

	t.Run("ConsumeTXCodeAttempt", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID: "contract-txcode-session",
			Code:      "contract-txcode-code",
			TXCode:    "123456",
		}
		require.NoError(t, store.Save(ctx, doc))

		for i := range MaxTXCodeAttempts {
			result, err := store.ConsumeTXCodeAttempt(ctx, "contract-txcode-code")
			require.NoError(t, err)
			assert.Equal(t, i+1, result.TXCodeAttempts)
			assert.False(t, result.Forfeited)
		}

		// One over the cap: forfeits and reports lockout
		_, err := store.ConsumeTXCodeAttempt(ctx, "contract-txcode-code")
		assert.ErrorIs(t, err, ErrTXCodeAttemptsExceeded)

		locked, err := store.GetByAuthorizationCode(ctx, "contract-txcode-code")
		require.NoError(t, err)
		assert.True(t, locked.Forfeited)

		// After forfeiture, further calls surface the forfeited state, not lockout.
		_, err = store.ConsumeTXCodeAttempt(ctx, "contract-txcode-code")
		assert.Error(t, err)
		assert.NotErrorIs(t, err, ErrTXCodeAttemptsExceeded)

		// Unknown code
		_, err = store.ConsumeTXCodeAttempt(ctx, "contract-txcode-missing")
		assert.ErrorIs(t, err, ErrNoDocuments)
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, store.Delete(ctx, "contract-session-1"))

		_, err := store.GetByID(ctx, "contract-session-1")
		assert.ErrorIs(t, err, ErrNoDocuments)
	})

	t.Run("Create_Alias", func(t *testing.T) {
		doc := &AuthorizationContext{
			SessionID: "contract-create-alias",
			Code:      "create-alias-code",
		}
		require.NoError(t, store.Create(ctx, doc))

		result, err := store.GetByID(ctx, "contract-create-alias")
		require.NoError(t, err)
		assert.Equal(t, "contract-create-alias", result.SessionID)
	})

	t.Run("SaveNilDoc", func(t *testing.T) {
		assert.Error(t, store.Save(ctx, nil))
	})

	t.Run("SaveEmptySessionID", func(t *testing.T) {
		assert.Error(t, store.Save(ctx, &AuthorizationContext{}))
	})

	t.Run("GetNilQuery", func(t *testing.T) {
		_, err := store.Get(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		_, err := store.GetByID(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrNoDocuments)
	})

	t.Run("GetByAccessToken_Empty", func(t *testing.T) {
		_, err := store.GetByAccessToken(ctx, "")
		assert.Error(t, err)
	})

	// The one-shot guarantee the Authorization Challenge Endpoint runs on,
	// asserted against every backend rather than only the one the handler
	// tests happen to use.
	//
	// It is implemented differently in each - a locked read-modify-write in
	// memory, a single FindOneAndUpdate in MongoDB - and MongoDB is the
	// deployment where it matters, because that is where two APIGW
	// instances can be answering the same wallet's retry at once. A
	// contract that is only exercised in memory says nothing about the
	// implementation that carries the risk.
	t.Run("ClaimAuthSession", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:                 "contract-claim-1",
			Code:                      "contract-claim-code-1",
			AuthSession:               "contract-handle-1",
			AuthSessionDPoPThumbprint: "contract-thumbprint-1",
		}))

		claimed, err := store.ClaimAuthSession(ctx, "contract-handle-1")
		require.NoError(t, err)
		require.NotNil(t, claimed)

		// The claimant is handed the exchange as it was, because the DPoP
		// binding is what the authorization code inherits...
		assert.Equal(t, "contract-thumbprint-1", claimed.AuthSessionDPoPThumbprint)
		// ...but not the handle. Anything downstream that persists this
		// document would otherwise write it straight back.
		assert.Empty(t, claimed.AuthSession)

		// Exactly one claimant: the second request finds nothing, whether
		// it is a retry or the other half of a race.
		second, err := store.ClaimAuthSession(ctx, "contract-handle-1")
		assert.ErrorIs(t, err, ErrNoDocuments)
		assert.Nil(t, second)

		// And the handle stops resolving, while the context it named
		// stays reachable by the code it produced.
		_, err = store.Get(ctx, &AuthorizationContext{AuthSession: "contract-handle-1"})
		assert.ErrorIs(t, err, ErrNoDocuments)

		stored, err := store.GetByID(ctx, "contract-claim-1")
		require.NoError(t, err)
		assert.Empty(t, stored.AuthSession)
		assert.Equal(t, "contract-thumbprint-1", stored.AuthSessionDPoPThumbprint)
	})

	// Sequentially, the second claim arrives after the first has finished.
	// The case the implementation actually has to survive is the one where
	// it does not - two APIGW instances answering the same wallet's retry
	// at the same moment - and that is a property of the STORE, which is
	// why it is asserted here against each of them.
	t.Run("ClaimAuthSession_Concurrent", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:                 "contract-claim-race",
			Code:                      "contract-claim-race-code",
			AuthSession:               "contract-handle-race",
			AuthSessionDPoPThumbprint: "contract-thumbprint-race",
		}))

		const contenders = 8
		var (
			start     sync.WaitGroup
			finished  sync.WaitGroup
			succeeded atomic.Int32
		)
		start.Add(1)
		finished.Add(contenders)

		for range contenders {
			go func() {
				defer finished.Done()
				start.Wait()
				claimed, err := store.ClaimAuthSession(ctx, "contract-handle-race")
				if err == nil && claimed != nil {
					succeeded.Add(1)
				}
			}()
		}
		start.Done()
		finished.Wait()

		assert.Equal(t, int32(1), succeeded.Load(),
			"exactly one of %d concurrent claimants may take the handle", contenders)
	})

	t.Run("ClaimAuthSession_Unknown", func(t *testing.T) {
		claimed, err := store.ClaimAuthSession(ctx, "contract-handle-never-issued")
		assert.ErrorIs(t, err, ErrNoDocuments)
		assert.Nil(t, claimed)
	})

	// ExtendExpiry never shortens, and nothing else may shorten behind it.
	//
	// The guarantee is implemented with $max in MongoDB, which protects
	// concurrent ExtendExpiry calls against each other - and protects
	// nothing at all from a whole-document write that carries an older
	// expires_at. /authorize does exactly that a moment later when it
	// records the auth provider, so the two have to be tested together or
	// the guarantee is only true in isolation.
	t.Run("SetAuthProviderPreservesExtendedExpiry", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:  "contract-provider-1",
			RequestURI: "https://example.com/req-provider-1",
			Code:       "contract-provider-code-1",
			ExpiresAt:  time.Now().Add(time.Minute).Unix(),
		}))

		// The deadline as a slower concurrent request would have read it,
		// before the extension. Copied out by value: the memory store
		// hands back the pointer it holds, so the document itself would
		// follow the extension and prove nothing.
		before, err := store.GetByID(ctx, "contract-provider-1")
		require.NoError(t, err)
		staleExpiresAt := before.ExpiresAt

		extended := time.Now().Add(10 * time.Minute).Unix()
		require.NoError(t, store.ExtendExpiry(ctx,
			&AuthorizationContext{RequestURI: "https://example.com/req-provider-1"}, extended))

		require.NoError(t, store.SetAuthProvider(ctx, "contract-provider-1", AuthProviderFields{
			AuthProvider:    "openid4vp",
			DataSource:      "datastore",
			RemoteName:      "remote",
			AuthenticSource: "source",
		}))

		result, err := store.GetByID(ctx, "contract-provider-1")
		require.NoError(t, err)
		assert.Equal(t, "openid4vp", result.AuthProvider)
		assert.Equal(t, "datastore", result.DataSource)
		assert.Equal(t, "remote", result.RemoteName)
		assert.Equal(t, "source", result.AuthenticSource)
		assert.Equal(t, extended, result.ExpiresAt,
			"recording the auth provider must not write back an older deadline")
		assert.Less(t, staleExpiresAt, result.ExpiresAt,
			"the test is only meaningful if the extension actually moved the deadline")
	})

	// ExtendExpiry has to answer to a session_id as well as a request_uri:
	// an Interactive Authorization exchange has just had its auth_session
	// claimed when its code's life begins, so there is no handle left to
	// name it by.
	t.Run("ExtendExpiryBySessionID", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID: "contract-extend-1",
			Code:      "contract-extend-code-1",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
		}))

		extended := time.Now().Add(10 * time.Minute).Unix()
		require.NoError(t, store.ExtendExpiry(ctx,
			&AuthorizationContext{SessionID: "contract-extend-1"}, extended))

		result, err := store.GetByID(ctx, "contract-extend-1")
		require.NoError(t, err)
		assert.Equal(t, extended, result.ExpiresAt)

		// And still never shortens.
		require.NoError(t, store.ExtendExpiry(ctx,
			&AuthorizationContext{SessionID: "contract-extend-1"}, time.Now().Add(time.Second).Unix()))
		result, err = store.GetByID(ctx, "contract-extend-1")
		require.NoError(t, err)
		assert.Equal(t, extended, result.ExpiresAt, "ExtendExpiry must never shorten")
	})

	// The issuer-initiated handle has to be replaced BY the opened
	// exchange, in one mutation.
	//
	// Claiming and then persisting as two writes has a failure mode with
	// no recovery: the claim lands, the persist does not, and the document
	// has lost its issuer_state without ever gaining an auth_session - so
	// the prepared issuance is unreachable by either handle and nothing,
	// including the issuer that prepared it, can get it back. There is no
	// state in which that is true here, because there is only one write.
	t.Run("ClaimIssuerState", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:   "contract-issuer-1",
			Code:        "contract-issuer-code-1",
			IssuerState: "contract-issuer-handle-1",
		}))

		opened, err := store.GetByID(ctx, "contract-issuer-1")
		require.NoError(t, err)
		toStore := *opened
		toStore.AuthSession = "contract-issuer-auth-session-1"
		toStore.AuthSessionDPoPThumbprint = "contract-issuer-thumbprint-1"
		toStore.WalletClientID = "wallet-1"

		claimed, err := store.ClaimIssuerState(ctx, "contract-issuer-handle-1", &toStore)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Empty(t, claimed.IssuerState)
		assert.Equal(t, "contract-issuer-auth-session-1", claimed.AuthSession)
		assert.Equal(t, "wallet-1", claimed.WalletClientID)

		// The handle is spent and the exchange is open, both at once:
		// there is no observable moment with neither.
		_, err = store.Get(ctx, &AuthorizationContext{IssuerState: "contract-issuer-handle-1"})
		assert.ErrorIs(t, err, ErrNoDocuments)

		byHandle, err := store.Get(ctx, &AuthorizationContext{AuthSession: "contract-issuer-auth-session-1"})
		require.NoError(t, err, "the exchange the claim opened must be resolvable by its auth_session")
		assert.Equal(t, "contract-issuer-1", byHandle.SessionID)

		// Exactly one claimant: an issuance prepared for one Holder opens
		// one exchange, not one per wallet that scans the offer.
		second, err := store.ClaimIssuerState(ctx, "contract-issuer-handle-1", &toStore)
		assert.ErrorIs(t, err, ErrNoDocuments)
		assert.Nil(t, second)
	})

	t.Run("ClaimIssuerState_Concurrent", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:   "contract-issuer-race",
			Code:        "contract-issuer-race-code",
			IssuerState: "contract-issuer-handle-race",
		}))

		base, err := store.GetByID(ctx, "contract-issuer-race")
		require.NoError(t, err)

		const contenders = 8
		var (
			start     sync.WaitGroup
			finished  sync.WaitGroup
			succeeded atomic.Int32
		)
		start.Add(1)
		finished.Add(contenders)

		for i := range contenders {
			go func() {
				defer finished.Done()
				opened := *base
				opened.AuthSession = fmt.Sprintf("contract-issuer-race-session-%d", i)
				start.Wait()
				claimed, err := store.ClaimIssuerState(ctx, "contract-issuer-handle-race", &opened)
				if err == nil && claimed != nil {
					succeeded.Add(1)
				}
			}()
		}
		start.Done()
		finished.Wait()

		assert.Equal(t, int32(1), succeeded.Load(),
			"exactly one of %d concurrent claimants may open the prepared issuance", contenders)
	})

	t.Run("ClaimIssuerState_Unknown", func(t *testing.T) {
		claimed, err := store.ClaimIssuerState(ctx, "contract-issuer-never-prepared",
			&AuthorizationContext{SessionID: "contract-issuer-1"})
		assert.ErrorIs(t, err, ErrNoDocuments)
		assert.Nil(t, claimed)
	})

	t.Run("ClaimIssuerState_Empty", func(t *testing.T) {
		_, err := store.ClaimIssuerState(ctx, "", &AuthorizationContext{SessionID: "contract-issuer-1"})
		assert.Error(t, err)

		_, err = store.ClaimIssuerState(ctx, "contract-issuer-handle-1", nil)
		assert.Error(t, err)
	})

	t.Run("ClaimAuthSession_Empty", func(t *testing.T) {
		_, err := store.ClaimAuthSession(ctx, "")
		assert.Error(t, err)
	})
}
