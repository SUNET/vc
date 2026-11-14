package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/resourcereach"
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
	results, err := store.SearchMappings(ctx, &SearchMappingsQuery{Search: "Karlsson", Reach: resourcereach.Everything()})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "person-3", results[0].AuthenticSourcePersonID)

	// SearchMappings: filter by authentic_source.
	results, err = store.SearchMappings(ctx, &SearchMappingsQuery{AuthenticSource: "OTHER", Reach: resourcereach.Everything()})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// DeleteMapping.
	require.NoError(t, store.DeleteMapping(ctx, &DeleteMappingQuery{AuthenticSource: "SUNET", AuthenticSourcePersonID: "person-1"}))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	err = store.DeleteMapping(ctx, &DeleteMappingQuery{AuthenticSource: "SUNET", AuthenticSourcePersonID: "person-1"})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)

	// SUNET/vc#507: two people can share a name across namespaces, and
	// resolving without naming one used to search all of them and return
	// whichever the store reached first - somebody else's identity. Both
	// identities are created here rather than reused from above, because
	// person-1 has been deleted by this point.
	twins := []*model.IdentityMapping{
		{
			AuthenticSource:         "TAX_AUTHORITY",
			AuthenticSourcePersonID: "tax-person",
			Attributes:              map[string]string{"family_name": "Twin", "given_name": "Sam"},
		},
		{
			AuthenticSource:         "HEALTH_AUTHORITY",
			AuthenticSourcePersonID: "health-person",
			Attributes:              map[string]string{"family_name": "Twin", "given_name": "Sam"},
		},
	}
	require.NoError(t, store.CreateMappings(ctx, twins))

	_, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
		Attributes: map[string]string{"family_name": "Twin", "given_name": "Sam"},
	})
	assert.ErrorIs(t, err, helpers.ErrIdentityMappingNamespaceRequired,
		"an unnamespaced resolve can only return an arbitrary one of the two")

	// Naming the namespace resolves, and resolves to the right person.
	for _, twin := range twins {
		personID, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
			AuthenticSource: twin.AuthenticSource,
			Attributes:      map[string]string{"family_name": "Twin", "given_name": "Sam"},
		})
		require.NoError(t, err)
		assert.Equal(t, twin.AuthenticSourcePersonID, personID,
			"the namespace must decide which identity is returned")
	}

	// A namespace that exists with attributes that do not still finds
	// nothing, rather than falling back to the other namespace.
	_, err = store.ResolveMapping(ctx, &ResolveMappingQuery{
		AuthenticSource: "TAX_AUTHORITY",
		Attributes:      map[string]string{"family_name": "Nobody"},
	})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)

	testIdentityMappingReachContract(t, store)
}

// testIdentityMappingReachContract holds the guarantee of the source filter on one
// store: a mapping comes back only when the engine allows its source with scope
// identity_mapping.
func testIdentityMappingReachContract(t *testing.T, store IdentityMappingStore) {
	t.Helper()
	ctx := t.Context()

	const term = "reach-person"
	sources := []string{"A", "B", "a", "A "}
	for i, source := range sources {
		require.NoError(t, store.CreateMapping(ctx, &model.IdentityMapping{
			AuthenticSource:         source,
			AuthenticSourcePersonID: term + "-" + string(rune('0'+i)),
			Attributes:              map[string]string{"family_name": "x"},
		}))
	}

	rule := func(source, scope string) string {
		return "(vc (service apigw)(method GET)(path /p)(subject alice)(authentic_source " + source + ")(scope " + scope + "))"
	}
	for _, row := range []struct {
		name   string
		rules  []string
		source string
		// leftOut: a form outside the filter, so the result is a subset.
		leftOut bool
	}{
		{name: "no rule", rules: []string{"(vc (service apigw)(method GET)(path /p)(subject bob)(authentic_source *)(scope *))"}},
		{name: "other scope", rules: []string{rule("A", "pid")}},
		{name: "its scope", rules: []string{rule("A", "identity_mapping")}},
		{name: "paired with another scope", rules: []string{rule("A", "identity_mapping"), rule("B", "pid")}},
		{name: "wildcard scope", rules: []string{rule("(* set A B)", "*")}},
		{name: "wildcard source", rules: []string{rule("*", "identity_mapping")}},
		{name: "everything", rules: []string{rule("*", "*")}},
		{name: "scope form", rules: []string{rule("B", "identity*")}},
		{name: "lower case value", rules: []string{rule("a", "identity_mapping")}},
		{name: "named source within sources", rules: []string{rule("(* set A B)", "identity_mapping")}, source: "A"},
		{name: "named lower case source", rules: []string{rule("*", "*")}, source: "a"},
		{name: "source form", rules: []string{rule("(* prefix A)", "identity_mapping")}, leftOut: true},
		{name: "source form, named", rules: []string{rule("(* prefix A)", "identity_mapping")}, source: "A"},
	} {
		t.Run(row.name, func(t *testing.T) {
			engine, err := httphelpers.BuildSPOCPEngine(model.APIAuth{Rules: row.rules})
			require.NoError(t, err)
			reach, err := resourcereach.Resolve(engine, "apigw", "GET", "/p", "alice")
			require.NoError(t, err)

			want := []string{}
			for _, source := range sources {
				if (row.source == "" || row.source == source) &&
					engine.QueryElement(httphelpers.BuildSPOCPQuery("apigw", "GET", "/p", "alice", source, resourcereach.IdentityMappingScope)) {
					want = append(want, source)
				}
			}

			found, err := store.SearchMappings(ctx, &SearchMappingsQuery{
				Search: term, AuthenticSource: row.source, Limit: 200, Reach: reach.Selecting(row.source, ""),
			})
			require.NoError(t, err)
			received := make([]string, 0, len(found))
			for _, mapping := range found {
				received = append(received, mapping.AuthenticSource)
			}
			if row.leftOut {
				assert.Subset(t, want, received)
				return
			}
			assert.ElementsMatch(t, want, received)
		})
	}

	// The zero value matches no mapping.
	found, err := store.SearchMappings(ctx, &SearchMappingsQuery{Search: term})
	require.NoError(t, err)
	assert.Empty(t, found)
}

func TestSQLIdentityMappingsColl_Postgres(t *testing.T) {
	sqlDB, dialect := sqltest.StartPostgres(t)

	testIdentityMappingStoreContract(t, NewSQLIdentityMappingsColl(newTestService(t), sqlDB, dialect))
}

func TestSQLIdentityMappingsColl_MariaDB(t *testing.T) {
	sqlDB, dialect := sqltest.StartMariaDB(t)

	testIdentityMappingStoreContract(t, NewSQLIdentityMappingsColl(newTestService(t), sqlDB, dialect))
}
