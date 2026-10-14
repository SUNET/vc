package cache

import (
	"context"
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

	t.Run("GetSnapshotIsolatesTheCallerAndGetDoesNot", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID: "contract-snapshot-1",
			State:     "contract-snapshot-state",
			Code:      "contract-snapshot-code",
		}))
		query := &AuthorizationContext{State: "contract-snapshot-state"}

		// GetSnapshot is for readers. What it returns is the caller's,
		// so the store cannot be changed by assigning to it - and, the
		// point of the method, reading it cannot race with a concurrent
		// claim mutating the stored document.
		snapshot, err := store.GetSnapshot(ctx, query)
		require.NoError(t, err)
		snapshot.Identifier = "scribbled-on"

		after, err := store.GetSnapshot(ctx, query)
		require.NoError(t, err)
		assert.Empty(t, after.Identifier, "a snapshot must not be a handle on the store")

		// Get is for read-modify-Update, and must keep working that way:
		// handing those callers a snapshot would turn their Update into a
		// lost update against anything the store changed in between.
		live, err := store.Get(ctx, query)
		require.NoError(t, err)
		live.Identifier = "written-back"
		require.NoError(t, store.Update(ctx, live))

		persisted, err := store.GetSnapshot(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, "written-back", persisted.Identifier)
	})

	t.Run("ResumeIssuerState", func(t *testing.T) {
		require.NoError(t, store.Save(ctx, &AuthorizationContext{
			SessionID:   "contract-resume-1",
			IssuerState: "contract-issuer-state-1",
			Scopes:      []string{"pid"},
		}))

		resumed, err := store.ResumeIssuerState(ctx, "contract-issuer-state-1", &IssuerStateResume{
			AuthSession:               "contract-auth-session-1",
			AuthSessionDPoPThumbprint: "contract-thumbprint",
			WalletClientID:            "wallet-1",
			CodeChallenge:             "contract-challenge",
			CodeChallengeMethod:       "S256",
			ExpiresAt:                 time.Now().Add(time.Hour).Unix(),
			CreatedAt:                 time.Now(),
		})
		require.NoError(t, err)

		// One operation: the handle is gone AND the exchange is written.
		// Observing one without the other is the window this method
		// exists to close.
		assert.Empty(t, resumed.IssuerState)
		assert.Equal(t, "contract-auth-session-1", resumed.AuthSession)
		assert.Equal(t, "contract-thumbprint", resumed.AuthSessionDPoPThumbprint)
		assert.Equal(t, "wallet-1", resumed.WalletClientID)
		assert.Equal(t, []string{"pid"}, resumed.Scopes, "the prepared issuance survives the resume")

		stored, err := store.Get(ctx, &AuthorizationContext{AuthSession: "contract-auth-session-1"})
		require.NoError(t, err)
		assert.Equal(t, "contract-resume-1", stored.SessionID)

		// And it is one-shot, for the same reason ClaimIssuerState is:
		// two wallets scanning one offer must yield exactly one winner.
		second, err := store.ResumeIssuerState(ctx, "contract-issuer-state-1", &IssuerStateResume{
			AuthSession: "contract-auth-session-2",
		})
		require.ErrorIs(t, err, ErrNoDocuments)
		assert.Nil(t, second)
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
}

// Get hands a caller the stored document, which is what keeps a
// read-modify-Update caller from erasing an in-store mutation that landed
// in between: the forfeited code it writes back is the same struct the
// forfeit was recorded on.
//
// That is the property this PR relied on when it narrowed its snapshot to
// GetSnapshot instead of changing Get, so it is pinned here rather than
// left as an observation.
//
// NOT a shared contract test, because MongoStore does not have this
// property and never did: every Mongo read decodes a fresh struct and
// Update replaces the document, so the same interleaving loses the
// forfeit there. That divergence is real and predates this change - it is
// the wider lost-update hazard in Update, which wants version-checked
// writes to fix properly - and asserting it as a contract both backends
// meet would be asserting something false.
func TestMemoryStore_GetKeepsAConcurrentForfeitVisible(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(5 * time.Minute)

	require.NoError(t, store.Save(ctx, &AuthorizationContext{
		SessionID: "forfeit-1",
		Code:      "forfeit-code",
	}))

	// What a read-modify-Update caller does: read, change a field of its
	// own, write back.
	held, err := store.Get(ctx, &AuthorizationContext{SessionID: "forfeit-1"})
	require.NoError(t, err)
	held.AuthProvider = "some-provider"

	// Meanwhile the code is redeemed and consumed.
	_, err = store.ForfeitAuthorizationCode(ctx, &AuthorizationContext{Code: "forfeit-code"})
	require.NoError(t, err)

	require.NoError(t, store.Update(ctx, held))

	after, err := store.GetSnapshot(ctx, &AuthorizationContext{SessionID: "forfeit-1"})
	require.NoError(t, err)
	assert.True(t, after.Forfeited,
		"a consumed code must not be resurrected by a caller that read before it was consumed")
	assert.Equal(t, "some-provider", after.AuthProvider, "and the caller's own change must still land")
}
