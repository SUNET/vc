package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIdentityMappingStoreContract(t *testing.T, store IdentityMappingStore) {
	t.Helper()
	ctx := t.Context()

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)

	m1 := &model.IdentityMapping{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "person-1",
		Attributes: map[string]string{
			"family_name": "Svensson",
			"given_name":  "Magnus",
			"birth_date":  "1970-01-01",
		},
	}
	require.NoError(t, store.CreateMapping(ctx, m1))

	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// ResolveMapping by authentic_source + attributes.
	personID, err := store.ResolveMapping(ctx, &ResolveMappingQuery{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson", "given_name": "Magnus"},
	})
	require.NoError(t, err)
	assert.Equal(t, "person-1", personID)

	// ResolveMapping with a non-matching attribute should not find it.
	_, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Nomatch"},
	})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)

	// EnsureMapping on an existing key must leave attributes unchanged.
	require.NoError(t, store.EnsureMapping(ctx, &model.IdentityMapping{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "person-1",
		Attributes:              map[string]string{"family_name": "ShouldNotOverwrite"},
	}))
	personID, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson"},
	})
	require.NoError(t, err)
	assert.Equal(t, "person-1", personID)

	// EnsureMapping on a new key creates it.
	require.NoError(t, store.EnsureMapping(ctx, &model.IdentityMapping{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "person-2",
		Attributes:              map[string]string{"family_name": "Andersson"},
	}))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// CreateMappings bulk insert.
	require.NoError(t, store.CreateMappings(ctx, []*model.IdentityMapping{
		{AuthenticSource: "OTHER", AuthenticSourcePersonID: "person-3", Attributes: map[string]string{"family_name": "Karlsson"}},
		{AuthenticSource: "OTHER", AuthenticSourcePersonID: "person-4", Attributes: map[string]string{"family_name": "Nilsson"}},
	}))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), count)

	// UpdateMapping.
	require.NoError(t, store.UpdateMapping(ctx, &model.IdentityMapping{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "person-1",
		Attributes:              map[string]string{"family_name": "Updated"},
	}))
	personID, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Updated"},
	})
	require.NoError(t, err)
	assert.Equal(t, "person-1", personID)

	// UpdateMapping on a nonexistent key.
	err = store.UpdateMapping(ctx, &model.IdentityMapping{AuthenticSource: "NOPE", AuthenticSourcePersonID: "nope"})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)

	// SearchMappings: free-text search over family_name.
	results, err := store.SearchMappings(ctx, &SearchMappingsQuery{Search: "Karlsson"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "person-3", results[0].AuthenticSourcePersonID)

	// SearchMappings: filter by authentic_source.
	results, err = store.SearchMappings(ctx, &SearchMappingsQuery{AuthenticSource: "OTHER"})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// SearchMappings: AllowedAuthenticSources restriction blocks a disallowed source.
	results, err = store.SearchMappings(ctx, &SearchMappingsQuery{
		AuthenticSource:         "SUNET",
		AllowedAuthenticSources: []string{"OTHER"},
	})
	require.NoError(t, err)
	assert.Empty(t, results)

	// DeleteMapping.
	require.NoError(t, store.DeleteMapping(ctx, &DeleteMappingQuery{AuthenticSource: "SUNET", AuthenticSourcePersonID: "person-1"}))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	err = store.DeleteMapping(ctx, &DeleteMappingQuery{AuthenticSource: "SUNET", AuthenticSourcePersonID: "person-1"})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
}

func TestSQLIdentityMappingsColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testIdentityMappingStoreContract(t, NewSQLIdentityMappingsColl(newTestService(t), sqlDB, dialect))
}

func TestSQLIdentityMappingsColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testIdentityMappingStoreContract(t, NewSQLIdentityMappingsColl(newTestService(t), sqlDB, dialect))
}
