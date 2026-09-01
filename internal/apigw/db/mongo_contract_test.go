package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// newTestServiceWithMongo builds a *Service backed by a real Mongo client,
// for running the shared contract-test helpers against the existing Mongo
// store implementations -- the same assertions used against Postgres and
// MariaDB above, so behavioral drift between backends is caught by one
// shared test suite rather than three separate ones.
func newTestServiceWithMongo(t *testing.T, client *mongo.Client) *Service {
	t.Helper()
	log := testsupport.TestLogger(t)
	tracer := tracertest.New(t, nil, log, "apigw-db-mongo-contract-test")
	return &Service{MongoClient: client, tracer: tracer, log: log}
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
		Coll:    client.Database("vc").Collection("identity_mappings"),
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
		Coll:    client.Database("vc").Collection("datastore"),
		log:     testsupport.TestLogger(t),
	}
	require.NoError(t, store.createIndex(t.Context()))

	testDatastoreStoreContract(t, store)
}

func startMongoContainerForTest(t *testing.T) (*mongo.Client, func()) {
	t.Helper()
	_, client, cleanup := testsupport.StartMongoContainer(t)
	return client, cleanup
}
