package cache

import (
	"context"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// isDockerAvailable checks if Docker is accessible
func isDockerAvailable() bool {
	return testsupport.IsDockerAvailable()
}

// startMongoContainer spins up a throwaway MongoDB via testcontainers and
// returns a connected *mongo.Client plus a cleanup function.
func startMongoContainer(t *testing.T) (*mongo.Client, func()) {
	t.Helper()
	_, client, cleanup := testsupport.StartMongoContainer(t)
	return client, cleanup
}

// newMongoTestStore creates a MongoStore backed by a real testcontainer.
// Each call gets a unique collection to isolate test state.
func newMongoTestStore(t *testing.T, client *mongo.Client, name string) *MongoStore {
	t.Helper()
	ctx := t.Context()

	store, err := NewMongoStore(ctx, client, "test_cache", "auth_context_"+name, 10*time.Minute)
	require.NoError(t, err)
	return store
}

// ---------- Tests ----------

// TestMongoStoreImplementsInterface verifies MongoStore satisfies AuthContextStore.
func TestMongoStoreImplementsInterface(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	var store AuthContextStore = newMongoTestStore(t, client, "iface")
	require.NotNil(t, store)
}

// TestInterfaceContract_Mongo runs the shared contract tests against the MongoStore.
func TestInterfaceContract_Mongo(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "contract")
	runAuthContextStoreContractTests(t, store)
}

// TestNewMongoStore_NilClient verifies NewMongoStore rejects a nil client.
func TestNewMongoStore_NilClient(t *testing.T) {
	_, err := NewMongoStore(context.Background(), nil, "db", "coll", 5*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mongo client cannot be nil")
}

// TestMongoStore_DuplicateSessionID verifies that saving two docs with the same
// session_id fails thanks to the unique index.
func TestMongoStore_DuplicateSessionID(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "dup")
	ctx := t.Context()

	doc := &AuthorizationContext{SessionID: "dup-1", Code: "c1"}
	require.NoError(t, store.Save(ctx, doc))

	dup := &AuthorizationContext{SessionID: "dup-1", Code: "c2"}
	err := store.Save(ctx, dup)
	assert.Error(t, err, "expected duplicate key error")
}

// TestMongoStore_CreatedAtAutoPopulated verifies Save fills in CreatedAt.
func TestMongoStore_CreatedAtAutoPopulated(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "created_at")
	ctx := t.Context()

	doc := &AuthorizationContext{SessionID: "ts-1"}
	require.NoError(t, store.Save(ctx, doc))

	result, err := store.GetByID(ctx, "ts-1")
	require.NoError(t, err)
	assert.False(t, result.CreatedAt.IsZero(), "CreatedAt should be auto-populated")
}

// TestMongoStore_UpdateNonExistent verifies updating a missing doc returns ErrNoDocuments.
func TestMongoStore_UpdateNonExistent(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "upd_missing")
	ctx := t.Context()

	err := store.Update(ctx, &AuthorizationContext{SessionID: "ghost"})
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_ConsentNotFound verifies Consent on missing doc returns ErrNoDocuments.
func TestMongoStore_ConsentNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "consent_nf")
	ctx := t.Context()

	err := store.Consent(ctx, &AuthorizationContext{RequestURI: "https://nope"})
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_AddTokenNotFound verifies AddToken on missing doc returns ErrNoDocuments.
func TestMongoStore_AddTokenNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "token_nf")
	ctx := t.Context()

	err := store.AddToken(ctx, "no-such-code", &Token{AccessToken: "t", ExpiresAt: 1})
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_MarkCodeNotFound verifies MarkCodeAsForfeited on missing doc returns ErrNoDocuments.
func TestMongoStore_MarkCodeNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "mark_nf")
	ctx := t.Context()

	err := store.MarkCodeAsForfeited(ctx, "no-such-id")
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_SetAuthenticSourceNotFound verifies SetAuthenticSource on missing doc.
func TestMongoStore_SetAuthenticSourceNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "src_nf")
	ctx := t.Context()

	err := store.SetAuthenticSource(ctx, &AuthorizationContext{SessionID: "nope"}, "src")
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_SetIdentifier runs the full SetIdentifier flow.
func TestMongoStore_SetIdentifier(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "identity")
	ctx := t.Context()

	doc := &AuthorizationContext{SessionID: "id-1", RequestURI: "https://example.com/r"}
	require.NoError(t, store.Save(ctx, doc))

	require.NoError(t, store.SetIdentifier(ctx, &AuthorizationContext{SessionID: "id-1"}, "alice-id"))

	result, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, "alice-id", result.Identifier)
}

// TestMongoStore_SetIdentifierNotFound verifies SetIdentifier on missing doc.
func TestMongoStore_SetIdentifierNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "identity_nf")
	ctx := t.Context()

	err := store.SetIdentifier(ctx, &AuthorizationContext{SessionID: "nope"}, "ghost-id")
	assert.ErrorIs(t, err, ErrNoDocuments)
}

// TestMongoStore_GetByAllQueryFields verifies Get works for every indexed field.
func TestMongoStore_GetByAllQueryFields(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "query_fields")
	ctx := t.Context()

	doc := &AuthorizationContext{
		SessionID:                "qf-1",
		RequestURI:               "https://example.com/req",
		Code:                     "code-qf",
		State:                    "state-qf",
		VerifierResponseCode:     "vrc-qf",
		EphemeralEncryptionKeyID: "ek-qf",
		RequestObjectID:          "ro-qf",
	}
	require.NoError(t, store.Save(ctx, doc))

	tests := []struct {
		name  string
		query *AuthorizationContext
	}{
		{"BySessionID", &AuthorizationContext{SessionID: "qf-1"}},
		{"ByRequestURI", &AuthorizationContext{RequestURI: "https://example.com/req"}},
		{"ByCode", &AuthorizationContext{Code: "code-qf"}},
		{"ByState", &AuthorizationContext{State: "state-qf"}},
		{"ByVerifierResponseCode", &AuthorizationContext{VerifierResponseCode: "vrc-qf"}},
		{"ByEphemeralKeyID", &AuthorizationContext{EphemeralEncryptionKeyID: "ek-qf"}},
		{"ByRequestObjectID", &AuthorizationContext{RequestObjectID: "ro-qf"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := store.Get(ctx, tt.query)
			require.NoError(t, err)
			assert.Equal(t, "qf-1", result.SessionID)
		})
	}
}

// TestMongoStore_ForfeitByRequestURI verifies ForfeitAuthorizationCode via request_uri lookup.
func TestMongoStore_ForfeitByRequestURI(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "forfeit_uri")
	ctx := t.Context()

	doc := &AuthorizationContext{
		SessionID:  "forfeit-uri-1",
		RequestURI: "https://example.com/forfeit",
		Code:       "fc-1",
	}
	require.NoError(t, store.Save(ctx, doc))

	result, err := store.ForfeitAuthorizationCode(ctx, &AuthorizationContext{RequestURI: "https://example.com/forfeit"})
	require.NoError(t, err)
	assert.True(t, result.Forfeited)
}

// TestMongoStore_DeleteNonExistent verifies deleting a non-existent doc does not error.
func TestMongoStore_DeleteNonExistent(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "del_ne")
	ctx := t.Context()

	// MongoDB DeleteOne does not error when nothing matches
	err := store.Delete(ctx, "does-not-exist")
	assert.NoError(t, err)
}

// TestMongoStore_GetEmptyQuery verifies Get rejects an empty query.
func TestMongoStore_GetEmptyQuery(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "empty_q")
	ctx := t.Context()

	_, err := store.Get(ctx, &AuthorizationContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one search field")
}

// TestNewMongoStore_ViaContainer verifies NewMongoStore creates a working MongoStore.
func TestNewMongoStore_ViaContainer(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	store, err := NewMongoStore(t.Context(), client, "test_factory", "auth_ctx", 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, store)
}
