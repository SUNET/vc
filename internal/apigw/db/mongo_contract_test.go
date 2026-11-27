package db

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// newTestServiceWithMongo builds a *Service backed by a real Mongo client,
// for running the shared contract-test helpers against the existing Mongo
// store implementations -- the same assertions used against Postgres and
// MariaDB above, so behavioral drift between backends is caught by one
// shared test suite rather than three separate ones.
func newTestServiceWithMongo(t *testing.T, client *mongo.Client) *Service {
	t.Helper()
	var mongoCfg model.Mongo
	require.NoError(t, defaults.Set(&mongoCfg))
	return newTestServiceWithMongoDatabase(t, client, mongoCfg.APIGWDatabaseName)
}

// newTestServiceWithMongoDatabase is newTestServiceWithMongo with the apigw
// database name chosen by the caller.
func newTestServiceWithMongoDatabase(t *testing.T, client *mongo.Client, database string) *Service {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, nil, log, "apigw-db-mongo-contract-test")
	cfg := &model.Cfg{Common: &model.Common{Mongo: model.Mongo{APIGWDatabaseName: database}}}
	return &Service{MongoClient: client, cfg: cfg, tracer: tracer, log: log}
}

func TestCredentialOfferColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store, err := NewCredentialOfferColl(t.Context(), "credential_offer", svc, testsupport.TestLogger(t))
	require.NoError(t, err)

	testCredentialOfferStoreContract(t, store)
}

func TestDynamicRegistrationColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store, err := NewDynamicRegistrationColl(t.Context(), "oidc_dynamic_registration", svc, testsupport.TestLogger(t))
	require.NoError(t, err)

	testDynamicRegistrationStoreContract(t, store)
}

func TestIdentityMappingsColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store := &IdentityMappingsColl{
		Service: svc,
		Coll:    client.Database(svc.cfg.Common.Mongo.APIGWDatabaseName).Collection("identity_mappings"),
		log:     testsupport.TestLogger(t),
	}
	require.NoError(t, store.createIndex(t.Context()))

	testIdentityMappingStoreContract(t, store)
}

func TestDatastoreColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store := &DatastoreColl{
		Service: svc,
		Coll:    client.Database(svc.cfg.Common.Mongo.APIGWDatabaseName).Collection("datastore"),
		log:     testsupport.TestLogger(t),
	}
	require.NoError(t, store.createIndex(t.Context()))

	testDatastoreStoreContract(t, store)

	// A document stored before created_at existed has no value to keep, and the
	// request's value must not take its place.
	_, err := store.Coll.InsertOne(t.Context(), bson.D{{Key: "meta", Value: bson.D{
		{Key: "authentic_source", Value: "SUNET"}, {Key: "scope", Value: "pid"}, {Key: "document_id", Value: "no-created-at"},
	}}})
	require.NoError(t, err)
	replaced := mkDoc("SUNET", "pid", "no-created-at", []string{"identity-1"}, map[string]any{"family_name": "Replaced"})
	replaced.Meta.CreatedAt = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	require.NoError(t, store.Replace(t.Context(), replaced))
	full, err := store.GetByKey(t.Context(), "SUNET", "pid", "no-created-at")
	require.NoError(t, err)
	assert.Truef(t, full.Meta.CreatedAt.IsZero(), "created_at: read back %s", full.Meta.CreatedAt)
	assert.Equal(t, "Replaced", full.DocumentData["family_name"])
}

func startMongoContainerForTest(t *testing.T) (*mongo.Client, func()) {
	t.Helper()
	_, client, cleanup := testsupport.StartMongoContainer(t)
	return client, cleanup
}

// Two deployments sharing one MongoDB server are kept apart only by their
// apigw_database_name. Before it existed every apigw wrote to "vc", so one
// deployment could read the other's credential offers.
func TestCredentialOfferColl_Mongo_DatabaseNameIsolates(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	storeA, err := NewCredentialOfferColl(t.Context(), "credential_offer", newTestServiceWithMongoDatabase(t, client, "tenant_a"), testsupport.TestLogger(t))
	require.NoError(t, err)
	storeB, err := NewCredentialOfferColl(t.Context(), "credential_offer", newTestServiceWithMongoDatabase(t, client, "tenant_b"), testsupport.TestLogger(t))
	require.NoError(t, err)

	require.NoError(t, storeA.Save(t.Context(), &CredentialOfferDocument{
		UUID: "offer-a",
		CredentialOfferParameters: openid4vci.CredentialOfferParameters{
			CredentialIssuer:           "https://a.example.com",
			CredentialConfigurationIDs: []string{"pid"},
		},
	}))

	got, err := storeA.Get(t.Context(), "offer-a")
	require.NoError(t, err)
	assert.Equal(t, "https://a.example.com", got.CredentialOfferParameters.CredentialIssuer)

	_, err = storeB.Get(t.Context(), "offer-a")
	assert.Error(t, err, "tenant_b must not see an offer saved by tenant_a")

	names, err := client.ListDatabaseNames(t.Context(), map[string]any{"name": "vc"})
	require.NoError(t, err)
	assert.Empty(t, names, "nothing may be written to the legacy \"vc\" database when another name is configured")
}
