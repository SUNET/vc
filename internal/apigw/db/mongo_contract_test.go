package db

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/tracertest"

	"github.com/stretchr/testify/assert"
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

func TestNymAuthPSCColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store, err := NewNymAuthPSCColl(t.Context(), "nymauth_psc", svc, testsupport.TestLogger(t))
	require.NoError(t, err)

	testNymAuthPSCStoreContract(t, store)
}

// A reset interrupted between its two writes is completed by a retry.
//
// Mongo-specific, and deliberately so: the SQL store does both writes
// in one transaction and cannot reach this state, while this one has no
// transaction to lean on. Without the compensation the retry sees the
// evidence already used, returns success, and the audited commitment
// stays on record - an issuer reporting a reset that did not happen,
// which is the one answer an operator must never be given here.
func TestNymAuthPSCColl_MongoCompletesAnInterruptedReset(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store, err := NewNymAuthPSCColl(t.Context(), "nymauth_psc_interrupted", svc, testsupport.TestLogger(t))
	require.NoError(t, err)

	ctx := t.Context()
	subject := pscDigest("interrupted")
	psc := pscDigest("private-seed-interrupted")
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.Accept(ctx, subject, psc, now))

	record, err := store.Get(ctx, subject)
	require.NoError(t, err)
	require.NotNil(t, record, "the fixture must leave the record in place")

	// The audit row lands; the delete never does.
	_, err = store.ResetsColl.InsertOne(ctx, NymAuthPSCReset{
		SubjectKey:      subject,
		EvidenceRef:     "evidence-interrupted",
		ResetOf:         ResetOf(psc),
		ResetAcceptance: record.Acceptance,
		ApprovedBy:      "operator-i",
		ApprovedAt:      now,
	})
	require.NoError(t, err)

	// The retry finishes it.
	require.NoError(t, store.Reset(ctx, subject, "operator-i", "evidence-interrupted", now))

	record, err = store.Get(ctx, subject)
	require.NoError(t, err)
	assert.Nil(t, record, "a retry must complete the interrupted reset, not report success and leave it")

	trail, err := store.Resets(ctx, subject)
	require.NoError(t, err)
	assert.Len(t, trail, 1, "and must not write a second audit row")
}

// ...but a retry must NOT remove a commitment the subject has since
// re-established. The trail names a commitment; only that one is
// removed, and on a retry those two cases are indistinguishable from
// the subject key alone.
func TestNymAuthPSCColl_MongoRetryLeavesAReEstablishedRecord(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	svc := newTestServiceWithMongo(t, client)
	store, err := NewNymAuthPSCColl(t.Context(), "nymauth_psc_reestablished", svc, testsupport.TestLogger(t))
	require.NoError(t, err)

	ctx := t.Context()
	subject := pscDigest("reestablished")
	oldPSC := pscDigest("private-seed-old")
	newPSC := pscDigest("private-seed-new")
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	for _, reaccepted := range []string{newPSC, oldPSC} {
		// oldPSC is the case the commitment alone cannot tell apart:
		// the subject recovered with the same wallet and the same
		// seed, so the new record holds the value the reset audited.
		require.NoError(t, store.Erase(ctx, subject))
		require.NoError(t, store.Accept(ctx, subject, oldPSC, now))
		require.NoError(t, store.Reset(ctx, subject, "operator-r", "evidence-r", now))
		require.NoError(t, store.Accept(ctx, subject, reaccepted, now.Add(time.Hour)))

		require.NoError(t, store.Reset(ctx, subject, "operator-r", "evidence-r", now.Add(2*time.Hour)))

		record, err := store.Get(ctx, subject)
		require.NoErrorf(t, err, "re-accepted %s", reaccepted)
		require.NotNilf(t, record, "the re-established record must survive the replayed reset (re-accepted %s)", reaccepted)
		assert.Equal(t, reaccepted, record.PSC)
	}
}
