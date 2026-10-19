package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCredentialStatusBackendIsPartOfTheKey: the table records `backend`
// precisely because the list URI alone does not say who owns an entry, so
// two backends reusing one URI and index are two distinct entries, not one.
//
// With the backend left out of the key the second Save REPLACED the first,
// and the credential that mapping belonged to became unrevocable while its
// revocation was routed to the other service.
func testCredentialStatusBackendIsPartOfTheKey(t *testing.T, store CredentialStatusStore) {
	t.Helper()
	ctx := t.Context()

	const uri = "https://status.example.com/statuslists/1"

	require.NoError(t, store.Save(ctx, &CredentialStatusEntry{
		StatusListURI: uri, Index: 7, Identifier: "person-registry",
		Backend: "registry", Section: 3, AuthenticSource: "SUNET", Scope: "pid",
	}))
	require.NoError(t, store.Save(ctx, &CredentialStatusEntry{
		StatusListURI: uri, Index: 7, Identifier: "person-external",
		Backend: "status_service", AuthenticSource: "SUNET", Scope: "pid",
	}))

	registryEntries, err := store.SearchByIdentifier(ctx, "person-registry")
	require.NoError(t, err)
	require.Len(t, registryEntries, 1, "the registry entry must survive the external one being recorded")
	assert.Equal(t, "registry", registryEntries[0].Backend)
	assert.Equal(t, int64(3), registryEntries[0].Section)

	externalEntries, err := store.SearchByIdentifier(ctx, "person-external")
	require.NoError(t, err)
	require.Len(t, externalEntries, 1)
	assert.Equal(t, "status_service", externalEntries[0].Backend)

	// Re-saving the same entry still upserts rather than duplicating: the
	// key is the three columns together, not the backend on its own.
	require.NoError(t, store.Save(ctx, &CredentialStatusEntry{
		StatusListURI: uri, Index: 7, Identifier: "person-registry-renamed",
		Backend: "registry", Section: 3,
	}))
	stale, err := store.SearchByIdentifier(ctx, "person-registry")
	require.NoError(t, err)
	assert.Empty(t, stale, "the same (uri, idx, backend) is one row, updated in place")
	renamed, err := store.SearchByIdentifier(ctx, "person-registry-renamed")
	require.NoError(t, err)
	require.Len(t, renamed, 1)
}

func TestSQLCredentialStatusColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testCredentialStatusBackendIsPartOfTheKey(t, NewSQLCredentialStatusColl(newTestService(t), sqlDB, dialect))
}

func TestSQLCredentialStatusColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testCredentialStatusBackendIsPartOfTheKey(t, NewSQLCredentialStatusColl(newTestService(t), sqlDB, dialect))
}
