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
