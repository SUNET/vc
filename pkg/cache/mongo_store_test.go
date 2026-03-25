package cache

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// isDockerAvailable checks if Docker is accessible
func isDockerAvailable() bool {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerPath, "version")
	return cmd.Run() == nil
}

// startMongoContainer spins up a throwaway MongoDB via testcontainers and
// returns a connected *mongo.Client plus a cleanup function.
func startMongoContainer(t *testing.T) (*mongo.Client, func()) {
	t.Helper()

	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)

	req := testcontainers.ContainerRequest{
		Image:        "mongo:7",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		cancel()
		t.Fatalf("Failed to start MongoDB container: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "27017")
	if err != nil {
		cancel()
		t.Fatalf("Failed to get mapped port: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		cancel()
		t.Fatalf("Failed to get container host: %v", err)
	}

	uri := fmt.Sprintf("mongodb://%s:%s", host, mappedPort.Port())
	t.Logf("MongoDB container started at %s", uri)

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		cancel()
		t.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	cleanup := func() {
		client.Disconnect(ctx)
		container.Terminate(ctx)
		cancel()
	}

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

// TestMongoStore_AddIdentity runs the full AddIdentity flow.
func TestMongoStore_AddIdentity(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "identity")
	ctx := t.Context()

	doc := &AuthorizationContext{SessionID: "id-1", RequestURI: "https://example.com/r"}
	require.NoError(t, store.Save(ctx, doc))

	input := &AuthorizationContext{
		Identity:        &model.Identity{GivenName: "Alice", FamilyName: "Smith"},
		VCT:             "urn:vct:pid",
		AuthenticSource: "test-as",
	}

	// Lookup by RequestURI
	require.NoError(t, store.AddIdentity(ctx, &AuthorizationContext{RequestURI: "https://example.com/r"}, input))

	result, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, "Alice", result.Identity.GivenName)
	assert.Equal(t, "urn:vct:pid", result.VCT)
	assert.Equal(t, "test-as", result.AuthenticSource)
}

// TestMongoStore_AddIdentityNotFound verifies AddIdentity on missing doc.
func TestMongoStore_AddIdentityNotFound(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	store := newMongoTestStore(t, client, "identity_nf")
	ctx := t.Context()

	input := &AuthorizationContext{
		Identity: &model.Identity{GivenName: "Ghost"},
	}
	err := store.AddIdentity(ctx, &AuthorizationContext{SessionID: "nope"}, input)
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
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "mongo:7",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer container.Terminate(ctx)

	mappedPort, err := container.MappedPort(ctx, "27017")
	require.NoError(t, err)
	host, err := container.Host(ctx)
	require.NoError(t, err)

	uri := fmt.Sprintf("mongodb://%s:%s", host, mappedPort.Port())

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	require.NoError(t, err)

	store, err := NewMongoStore(ctx, client, "test_factory", "auth_ctx", 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, store)
}
