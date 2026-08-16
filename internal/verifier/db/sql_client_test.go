package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// newTestService builds a *Service suitable for exercising store
// implementations directly (bypassing New(), which would try to connect to
// MongoDB): only the fields the store implementations actually use
// (tracer, log) are populated.
func newTestService(t *testing.T) *Service {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, nil, log, "verifier-db-test")
	return &Service{tracer: tracer, log: log}
}

func testClientStoreContract(t *testing.T, store ClientStore) {
	t.Helper()
	ctx := t.Context()

	// Not found: GetByClientID returns nil, nil (not an error).
	got, err := store.GetByClientID(ctx, "client-1")
	require.NoError(t, err)
	assert.Nil(t, got)

	client := &Client{
		ClientID:                "client-1",
		ClientSecretHash:        "hash-1",
		RedirectURIs:            []string{"https://rp.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		AllowedScopes:           []string{"openid", "profile"},
		SubjectType:             "public",
		RequirePKCE:             true,
		ClientName:              "Test RP",
		Contacts:                []string{"admin@example.com"},
		JWKS:                    map[string]any{"keys": []any{}},
	}
	require.NoError(t, store.Create(ctx, client))

	got, err = store.GetByClientID(ctx, "client-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "hash-1", got.ClientSecretHash)
	assert.Equal(t, []string{"https://rp.example.com/callback"}, got.RedirectURIs)
	assert.Equal(t, []string{"authorization_code"}, got.GrantTypes)
	assert.True(t, got.RequirePKCE)
	assert.Equal(t, "Test RP", got.ClientName)
	assert.Equal(t, []string{"admin@example.com"}, got.Contacts)
	require.NotNil(t, got.JWKS)

	// Update replaces every column.
	client.ClientSecretHash = "hash-2"
	client.ClientName = "Updated RP"
	client.AllowedScopes = []string{"openid"}
	require.NoError(t, store.Update(ctx, client))

	got, err = store.GetByClientID(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "hash-2", got.ClientSecretHash)
	assert.Equal(t, "Updated RP", got.ClientName)
	assert.Equal(t, []string{"openid"}, got.AllowedScopes)

	// Update on a nonexistent client_id is a silent no-op (matches Mongo's
	// ReplaceOne without upsert).
	require.NoError(t, store.Update(ctx, &Client{ClientID: "nonexistent"}))

	// Delete.
	require.NoError(t, store.Delete(ctx, "client-1"))
	got, err = store.GetByClientID(ctx, "client-1")
	require.NoError(t, err)
	assert.Nil(t, got)

	// Delete of a nonexistent client_id is also a silent no-op.
	require.NoError(t, store.Delete(ctx, "client-1"))
}

func TestSQLClientColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testClientStoreContract(t, NewSQLClientColl(newTestService(t), sqlDB, dialect))
}

func TestSQLClientColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testClientStoreContract(t, NewSQLClientColl(newTestService(t), sqlDB, dialect))
}

func TestClientCollection_Mongo(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	svc := &Service{MongoClient: client, tracer: tracertest.New(t, nil, testsupport.TestLogger(t), "verifier-db-mongo-test"), log: testsupport.TestLogger(t)}
	coll := &ClientCollection{Service: svc, collection: mongoClientCollection(client)}
	require.NoError(t, coll.createIndex(t.Context()))

	testClientStoreContract(t, coll)
}

func mongoClientCollection(client *mongo.Client) *mongo.Collection {
	return client.Database("verifier").Collection("clients")
}
