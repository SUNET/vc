package db

import (
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
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
	listed, err := store.List(ctx, &ListQuery{IdentityMappingID: "identity-2"})
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
	results, err := store.Search(ctx, &SearchDocumentsQuery{Search: "Karlsson"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "doc-2", results[0].Meta.DocumentID)

	// Search by authentic_source filter.
	results, err = store.Search(ctx, &SearchDocumentsQuery{AuthenticSource: "OTHER"})
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Search respecting AllowedAuthenticSources restriction.
	results, err = store.Search(ctx, &SearchDocumentsQuery{AuthenticSource: "SUNET", AllowedAuthenticSources: []string{"OTHER"}})
	require.NoError(t, err)
	assert.Empty(t, results)

	// Replace
	replaced := mkDoc("SUNET", "pid", "doc-1", []string{"identity-9"}, map[string]any{"family_name": "Replaced"})
	require.NoError(t, store.Replace(ctx, replaced))
	full, err = store.GetByKey(ctx, "SUNET", "pid", "doc-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"identity-9"}, full.IdentityMappingIDs)
	assert.Equal(t, "Replaced", full.DocumentData["family_name"])

	// Replace on a nonexistent document is a silent no-op.
	require.NoError(t, store.Replace(ctx, mkDoc("NOPE", "x", "y", nil, nil)))

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
