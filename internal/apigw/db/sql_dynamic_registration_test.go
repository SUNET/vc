package db

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDynamicRegistrationStoreContract(t *testing.T, store DynamicRegistrationStore) {
	t.Helper()
	ctx := t.Context()

	// No row yet: Get returns nil, nil (not an error).
	got, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Nil(t, got)

	creds := &DynamicRegistrationCredentials{
		ClientID:                "client-1",
		ClientSecret:            "secret-1",
		RegistrationAccessToken: "rat-1",
		RegistrationClientURI:   "https://issuer.example.com/register/client-1",
	}
	require.NoError(t, store.Save(ctx, creds))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "client-1", got.ClientID)
	assert.Equal(t, "secret-1", got.ClientSecret)
	assert.WithinDuration(t, time.Now(), got.RegisteredAt, 5*time.Second)

	// Save again (upsert path) with an already-expired secret -- Get should
	// then report no usable credentials, mirroring the Mongo expiry check.
	creds2 := &DynamicRegistrationCredentials{
		ClientID:              "client-1",
		ClientSecret:          "secret-2",
		ClientSecretExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}
	require.NoError(t, store.Save(ctx, creds2))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "expired client secret should make Get report no credentials")

	testRegistrationLookupAndPruning(t, store)
}

// testRegistrationLookupAndPruning covers the two operations HA depends on.
//
// GetByClientID is how a callback landing on a replica that never saw the
// registration its flow began on resolves the right client, and pruning is
// what decides whether that row is still there to be found. Both predicates
// are hand-written per backend - a reversed comparison or a dropped `<> ?`
// is invisible to Save/Get, and the renewal tests use a recording fake that
// would not notice either.
func testRegistrationLookupAndPruning(t *testing.T, store DynamicRegistrationStore) {
	t.Helper()
	ctx := t.Context()
	now := time.Now()

	// Four registrations covering every arm of the predicate.
	rows := []*DynamicRegistrationCredentials{
		{ClientID: "keep", ClientSecret: "s-keep", ClientSecretExpiresAt: now.Add(-2 * time.Hour).Unix()},
		{ClientID: "expired", ClientSecret: "s-expired", ClientSecretExpiresAt: now.Add(-time.Hour).Unix()},
		{ClientID: "unexpired", ClientSecret: "s-unexpired", ClientSecretExpiresAt: now.Add(time.Hour).Unix()},
		{ClientID: "never", ClientSecret: "s-never", ClientSecretExpiresAt: 0},
	}
	for _, r := range rows {
		require.NoError(t, store.Save(ctx, r))
	}

	// "keep" is given an EXPIRED secret on purpose: the row to keep is
	// identified by client id, not by whether its secret is still good. A
	// backend that filtered on expiry alone would delete the registration
	// the renewal just installed.
	for _, r := range rows {
		got, err := store.GetByClientID(ctx, r.ClientID)
		require.NoError(t, err, r.ClientID)
		require.NotNil(t, got, "%s should be retrievable by client id", r.ClientID)
		assert.Equal(t, r.ClientID, got.ClientID)
		assert.Equal(t, r.ClientSecret, got.ClientSecret,
			"GetByClientID must return the named client's own secret")
		assert.Equal(t, r.ClientSecretExpiresAt, got.ClientSecretExpiresAt)
	}

	got, err := store.GetByClientID(ctx, "no-such-client")
	require.NoError(t, err, "an unknown client is not an error")
	assert.Nil(t, got)

	got, err = store.GetByClientID(ctx, "")
	require.NoError(t, err)
	assert.Nil(t, got, "no client id names no registration")

	// An empty keepClientID must not be read as "keep nothing".
	require.NoError(t, store.PruneExpiredRegistrations(ctx, "", now))
	for _, r := range rows {
		got, err := store.GetByClientID(ctx, r.ClientID)
		require.NoError(t, err)
		assert.NotNil(t, got, "%s must survive a prune with no client to keep", r.ClientID)
	}

	require.NoError(t, store.PruneExpiredRegistrations(ctx, "keep", now))

	for name, wantPresent := range map[string]bool{
		"keep":      true,  // named as the one to keep, expired secret notwithstanding
		"expired":   false, // the only row the predicate should remove
		"unexpired": true,  // another replica may be running on it
		"never":     true,  // 0 means "never expires" (RFC 7591 3.2.1), not "expired in 1970"
		"client-1":  false, // left expired by the caller above
	} {
		got, err := store.GetByClientID(ctx, name)
		require.NoError(t, err, name)
		if wantPresent {
			assert.NotNil(t, got, "%s should have survived pruning", name)
		} else {
			assert.Nil(t, got, "%s should have been pruned", name)
		}
	}
}

func TestSQLDynamicRegistrationColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testDynamicRegistrationStoreContract(t, NewSQLDynamicRegistrationColl(newTestService(t), sqlDB, dialect))
}

func TestSQLDynamicRegistrationColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testDynamicRegistrationStoreContract(t, NewSQLDynamicRegistrationColl(newTestService(t), sqlDB, dialect))
}
