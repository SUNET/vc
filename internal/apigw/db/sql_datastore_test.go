package db

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/resourcereach"
	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkDoc(authenticSource, scope, documentID string, identityIDs []string, data map[string]any) *model.CompleteDocument {
	return &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: authenticSource,
			Scope:           scope,
			DocumentID:      documentID,
		},
		IdentityMappingIDs: identityIDs,
		DocumentData:       data,
	}
}

func testDatastoreStoreContract(t *testing.T, store DatastoreStore) {
	t.Helper()
	ctx := t.Context()

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)

	doc1 := mkDoc("SUNET", "pid", "doc-1", []string{"identity-1"}, map[string]any{
		"family_name": "Svensson", "given_name": "Magnus", "email": "magnus@example.com",
	})
	require.NoError(t, store.Save(ctx, doc1))

	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Get
	got, err := store.Get(ctx, doc1.Meta)
	require.NoError(t, err)
	assert.Equal(t, "SUNET", got.Meta.AuthenticSource)
	gotData, ok := got.DocumentData.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Svensson", gotData["family_name"])

	// GetByKey
	full, err := store.GetByKey(ctx, "SUNET", "pid", "doc-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"identity-1"}, full.IdentityMappingIDs)

	// AddIdentity
	require.NoError(t, store.AddIdentity(ctx, &AddIdentityQuery{
		AuthenticSource: "SUNET", Scope: "pid", DocumentID: "doc-1",
		IdentityMappingIDs: []string{"identity-2"},
	}))
	full, err = store.GetByKey(ctx, "SUNET", "pid", "doc-1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"identity-1", "identity-2"}, full.IdentityMappingIDs)

	// AddIdentity on a nonexistent document.
	err = store.AddIdentity(ctx, &AddIdentityQuery{AuthenticSource: "NOPE", Scope: "x", DocumentID: "y", IdentityMappingIDs: []string{"z"}})
	assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)

	// GetByIdentity
	byIdentity, err := store.GetByIdentity(ctx, "pid", "identity-1")
	require.NoError(t, err)
	require.Contains(t, byIdentity, "SUNET")
	assert.Equal(t, "doc-1", byIdentity["SUNET"].Meta.DocumentID)

	// List
	listed, err := store.List(ctx, &ListQuery{IdentityMappingID: "identity-2", Reach: resourcereach.Everything()})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "doc-1", listed[0].Meta.DocumentID)

	// DeleteIdentity
	require.NoError(t, store.DeleteIdentity(ctx, &DeleteIdentityQuery{
		AuthenticSource: "SUNET", Scope: "pid", DocumentID: "doc-1", AuthenticSourcePersonID: "identity-2",
	}))
	full, err = store.GetByKey(ctx, "SUNET", "pid", "doc-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"identity-1"}, full.IdentityMappingIDs)

	// Second doc for Search/SaveMany/ListAuthenticSources coverage.
	doc2 := mkDoc("OTHER", "ehic", "doc-2", []string{"identity-3"}, map[string]any{"family_name": "Karlsson"})
	doc3 := mkDoc("OTHER", "ehic", "doc-3", []string{"identity-4"}, map[string]any{"family_name": "Nilsson"})
	require.NoError(t, store.SaveMany(ctx, []*model.CompleteDocument{doc2, doc3}))

	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	sources, err := store.ListAuthenticSources(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"OTHER", "SUNET"}, sources)

	// Search by free text across document_data.
	results, err := store.Search(ctx, &SearchDocumentsQuery{Search: "Karlsson", Reach: resourcereach.Everything()})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "doc-2", results[0].Meta.DocumentID)

	// Search by authentic_source filter.
	results, err = store.Search(ctx, &SearchDocumentsQuery{AuthenticSource: "OTHER", Reach: resourcereach.Everything()})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Replace
	replaced := mkDoc("SUNET", "pid", "doc-1", []string{"identity-9"}, map[string]any{"family_name": "Replaced"})
	require.NoError(t, store.Replace(ctx, replaced))
	full, err = store.GetByKey(ctx, "SUNET", "pid", "doc-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"identity-9"}, full.IdentityMappingIDs)
	assert.Equal(t, "Replaced", full.DocumentData["family_name"])

	// Replace on a nonexistent document is a silent no-op.
	require.NoError(t, store.Replace(ctx, mkDoc("NOPE", "x", "y", []string{"identity-x"}, map[string]any{"family_name": "Ghost"})))

	// Save with duplicate identity mapping IDs must not error - the SQL
	// backend's (authentic_source, scope, document_id, identity_mapping_id)
	// primary key can't represent a literal duplicate row, so it dedupes;
	// Mongo's array field has no such constraint and keeps the duplicate
	// verbatim. Both are acceptable (this only asserts every distinct ID
	// still resolves, not an exact-multiset match) - a caller-supplied
	// duplicate must never turn into a constraint-violation error on one
	// backend but not the other.
	dupDoc := mkDoc("SUNET", "pid", "doc-dup", []string{"dup-1", "dup-1", "dup-2"}, map[string]any{"family_name": "Duplicate"})
	require.NoError(t, store.Save(ctx, dupDoc))
	full, err = store.GetByKey(ctx, "SUNET", "pid", "doc-dup")
	require.NoError(t, err)
	assert.Contains(t, full.IdentityMappingIDs, "dup-1")
	assert.Contains(t, full.IdentityMappingIDs, "dup-2")
	require.NoError(t, store.DeleteByKey(ctx, "SUNET", "pid", "doc-dup"))

	// DeleteByKey
	require.NoError(t, store.DeleteByKey(ctx, "OTHER", "ehic", "doc-3"))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	err = store.DeleteByKey(ctx, "OTHER", "ehic", "doc-3")
	assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)

	// Delete (silent, no error even if nothing matches).
	require.NoError(t, store.Delete(ctx, &model.MetaData{AuthenticSource: "SUNET", Scope: "pid", DocumentID: "doc-1"}))
	require.NoError(t, store.Delete(ctx, &model.MetaData{AuthenticSource: "GONE", Scope: "x", DocumentID: "y"}))
	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	testDatastoreReachContract(t, store)
}

// testDatastoreReachContract holds the guarantee of the pair filter on one store:
// a document comes back only when the engine allows its source and scope. The
// fixture separates a value from its case and trailing-space variants, which a
// MariaDB collation folds together in a plain "=".
func testDatastoreReachContract(t *testing.T, store DatastoreStore) {
	t.Helper()
	ctx := t.Context()

	const identity = "reach-identity"
	stored := []*model.CompleteDocument{
		mkDoc("A", "pid", "reach-1", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("A", "ehic", "reach-2", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("B", "pid", "reach-3", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("B", "ehic", "reach-4", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("a", "pid", "reach-5", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("A ", "pid", "reach-6", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("A", "PID", "reach-7", []string{identity}, map[string]any{"family_name": "x"}),
		mkDoc("eu-1", "pid", "reach-8", []string{identity}, map[string]any{"family_name": "x"}),
	}
	require.NoError(t, store.SaveMany(ctx, stored))

	rule := func(source, scope string) string {
		return "(vc (service apigw)(method POST)(path /p)(subject alice)(authentic_source " + source + ")(scope " + scope + "))"
	}
	for _, row := range []struct {
		name          string
		rules         []string
		source, scope string
		// leftOut: a form outside the filter, so the result is a subset.
		leftOut bool
	}{
		{name: "no rule", rules: []string{"(vc (service apigw)(method POST)(path /p)(subject bob)(authentic_source *)(scope *))"}},
		{name: "one pair", rules: []string{rule("A", "pid")}},
		{name: "disjoint pairs", rules: []string{rule("A", "pid"), rule("B", "ehic")}},
		{name: "set", rules: []string{rule("(* set A B)", "(* set pid)")}},
		{name: "wildcard source", rules: []string{rule("*", "pid")}},
		{name: "wildcard scope", rules: []string{rule("A", "*")}},
		{name: "everything", rules: []string{rule("*", "*")}},
		{name: "lower case value", rules: []string{rule("a", "pid")}},
		{name: "named pair within disjoint pairs", rules: []string{rule("A", "pid"), rule("B", "ehic")}, source: "A", scope: "pid"},
		{name: "named source within disjoint pairs", rules: []string{rule("A", "pid"), rule("B", "ehic")}, source: "A"},
		{name: "named lower case source", rules: []string{rule("*", "*")}, source: "a"},
		{name: "named scope with wildcard source", rules: []string{rule("*", "pid")}, scope: "pid"},
		{name: "prefix source", rules: []string{rule("eu*", "pid")}, leftOut: true},
		{name: "prefix source, named", rules: []string{rule("eu*", "pid")}, source: "eu-1", scope: "pid"},
		{name: "suffix scope, named", rules: []string{rule("A", "(* suffix id)")}, source: "A", scope: "pid"},
	} {
		t.Run(row.name, func(t *testing.T) {
			engine, err := httphelpers.BuildSPOCPEngine(model.APIAuth{Rules: row.rules})
			require.NoError(t, err)
			reach, err := resourcereach.Resolve(engine, "apigw", "POST", "/p", "alice")
			require.NoError(t, err)
			reach = reach.Selecting(row.source, row.scope)

			want := []string{}
			for _, doc := range stored {
				if (row.source == "" || row.source == doc.Meta.AuthenticSource) && (row.scope == "" || row.scope == doc.Meta.Scope) &&
					engine.QueryElement(httphelpers.BuildSPOCPQuery("apigw", "POST", "/p", "alice", doc.Meta.AuthenticSource, doc.Meta.Scope)) {
					want = append(want, doc.Meta.DocumentID)
				}
			}
			compare := func(from string, received []string) {
				if row.leftOut {
					assert.Subset(t, want, received, "documents received from %s", from)
					return
				}
				assert.ElementsMatch(t, want, received, "documents received from %s", from)
			}

			listed, err := store.List(ctx, &ListQuery{IdentityMappingID: identity, AuthenticSource: row.source, Scope: row.scope, Reach: reach})
			require.NoError(t, err)
			listedIDs := make([]string, 0, len(listed))
			for _, doc := range listed {
				listedIDs = append(listedIDs, doc.Meta.DocumentID)
			}
			compare("List", listedIDs)

			// The search term has a condition of its own beside the pair condition.
			for _, term := range []string{"", identity} {
				found, err := store.Search(ctx, &SearchDocumentsQuery{Search: term, AuthenticSource: row.source, Scope: row.scope, Limit: 200, Reach: reach})
				require.NoError(t, err)
				foundIDs := make([]string, 0, len(found))
				for _, doc := range found {
					if strings.HasPrefix(doc.Meta.DocumentID, "reach-") {
						foundIDs = append(foundIDs, doc.Meta.DocumentID)
					}
				}
				compare("Search", foundIDs)
			}
		})
	}

	// The zero value matches no document.
	listed, err := store.List(ctx, &ListQuery{IdentityMappingID: identity})
	require.NoError(t, err)
	assert.Empty(t, listed)
	found, err := store.Search(ctx, &SearchDocumentsQuery{Search: identity})
	require.NoError(t, err)
	assert.Empty(t, found)
}

func TestSQLDatastoreColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testDatastoreStoreContract(t, NewSQLDatastoreColl(newTestService(t), sqlDB, dialect))
}

func TestSQLDatastoreColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testDatastoreStoreContract(t, NewSQLDatastoreColl(newTestService(t), sqlDB, dialect))
}
