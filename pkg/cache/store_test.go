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
