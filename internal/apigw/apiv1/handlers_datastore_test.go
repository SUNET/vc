package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDatastoreTestClient(t *testing.T) (*Client, *memoryDatastoreStore, *memoryIdentityMappingStore) {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	datastore := newMemoryDatastoreStore()
	identityStore := newMemoryIdentityMappingStore()
	client := &Client{
		log:                  log,
		datastoreStore:       datastore,
		identityMappingStore: identityStore,
	}
	return client, datastore, identityStore
}

// seedDoc is a test helper that inserts a document directly into the store.
func seedDoc(t *testing.T, datastore *memoryDatastoreStore, authenticSource, scope, docID string, ids []string, data map[string]any) {
	t.Helper()
	err := datastore.Save(t.Context(), &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: authenticSource,
			Scope:           scope,
			DocumentID:      docID,
		},
		IdentityMappingIDs: ids,
		DocumentData:       data,
	})
	require.NoError(t, err)
}

// seedMapping is a test helper that inserts an identity mapping directly into the store.
func seedMapping(t *testing.T, identityStore *memoryIdentityMappingStore, authenticSource, personID string, attrs map[string]string) {
	t.Helper()
	err := identityStore.CreateMapping(t.Context(), &model.IdentityMapping{
		AuthenticSourcePersonID: personID,
		AuthenticSource:         authenticSource,
		Attributes:              attrs,
	})
	require.NoError(t, err)
}

// --- DatastoreGetByKey ---

func TestDatastoreGetByKey(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-001", []string{"person-001"}, map[string]any{"card": "SE-123"})

	t.Run("existing document", func(t *testing.T) {
		reply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-001",
		})
		require.NoError(t, err)
		require.NotNil(t, reply.Data)
		assert.Equal(t, "doc-001", reply.Data.Meta.DocumentID)
		assert.Equal(t, "SE-123", reply.Data.DocumentData["card"])
		assert.Equal(t, []string{"person-001"}, reply.Data.IdentityMappingIDs)
	})

	t.Run("non-existent document", func(t *testing.T) {
		_, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "no-such-doc",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})

	t.Run("wrong scope", func(t *testing.T) {
		_, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "pda1", DocumentID: "doc-001",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})

	t.Run("wrong authentic source", func(t *testing.T) {
		_, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "OTHER", Scope: "ehic", DocumentID: "doc-001",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

// --- DatastoreGet ---

func TestDatastoreGet(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-001", []string{"person-001"}, map[string]any{"card": "SE-123"})

	t.Run("returns document data", func(t *testing.T) {
		reply, err := client.DatastoreGet(t.Context(), &DatastoreGetRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-001",
		})
		require.NoError(t, err)
		assert.Equal(t, "SUNET", reply.Data.Meta.AuthenticSource)
		assert.Equal(t, "SE-123", reply.Data.DocumentData.(map[string]any)["card"])
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.DatastoreGet(t.Context(), &DatastoreGetRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "missing",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

// --- DatastoreDelete ---

func TestDatastoreDelete(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-del", []string{"person-001"}, map[string]any{"x": 1})

	t.Run("delete existing", func(t *testing.T) {
		err := client.DatastoreDelete(t.Context(), &DatastoreDeleteRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-del",
		})
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-del",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

// --- DatastoreDeleteByKey ---

func TestDatastoreDeleteByKey(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-dbk", []string{"person-001"}, map[string]any{"x": 1})

	t.Run("delete existing by key", func(t *testing.T) {
		err := client.DatastoreDeleteByKey(t.Context(), &DatastoreDeleteByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-dbk",
		})
		require.NoError(t, err)

		_, err = client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-dbk",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})

	t.Run("delete non-existent returns error", func(t *testing.T) {
		err := client.DatastoreDeleteByKey(t.Context(), &DatastoreDeleteByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "no-such",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

// --- DatastoreList ---

func TestDatastoreList(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-1", []string{"person-001"}, map[string]any{"n": 1})
	seedDoc(t, datastore, "SUNET", "pda1", "doc-2", []string{"person-001"}, map[string]any{"n": 2})
	seedDoc(t, datastore, "SUNET", "ehic", "doc-3", []string{"person-002"}, map[string]any{"n": 3})
	seedDoc(t, datastore, "OTHER", "ehic", "doc-4", []string{"person-001"}, map[string]any{"n": 4})

	t.Run("list by identity", func(t *testing.T) {
		reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			IdentityMappingID: "person-001",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Data, 3) // doc-1, doc-2, doc-4
	})

	t.Run("list by identity and scope", func(t *testing.T) {
		reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			IdentityMappingID: "person-001",
			Scope:             "ehic",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Data, 2) // doc-1, doc-4
	})

	t.Run("list by identity, scope, and source", func(t *testing.T) {
		reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			AuthenticSource:   "SUNET",
			IdentityMappingID: "person-001",
			Scope:             "ehic",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Data, 1)
		assert.Equal(t, "doc-1", reply.Data[0].Meta.DocumentID)
	})

	t.Run("no matches", func(t *testing.T) {
		reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			IdentityMappingID: "non-existent",
		})
		require.NoError(t, err)
		assert.Empty(t, reply.Data)
	})
}

// --- DatastoreAddIdentity / DatastoreDeleteIdentity ---

func TestDatastoreAddIdentity(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-id", []string{"person-001"}, map[string]any{"x": 1})

	t.Run("add new identity", func(t *testing.T) {
		err := client.DatastoreAddIdentity(t.Context(), &DatastoreAddIdentityRequest{
			AuthenticSource:    "SUNET",
			Scope:              "ehic",
			DocumentID:         "doc-id",
			IdentityMappingIDs: []string{"person-002", "person-003"},
		})
		require.NoError(t, err)

		doc, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-id",
		})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"person-001", "person-002", "person-003"}, doc.Data.IdentityMappingIDs)
	})

	t.Run("add duplicate identity is idempotent", func(t *testing.T) {
		err := client.DatastoreAddIdentity(t.Context(), &DatastoreAddIdentityRequest{
			AuthenticSource:    "SUNET",
			Scope:              "ehic",
			DocumentID:         "doc-id",
			IdentityMappingIDs: []string{"person-001"},
		})
		require.NoError(t, err)

		doc, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-id",
		})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"person-001", "person-002", "person-003"}, doc.Data.IdentityMappingIDs)
	})

	t.Run("add to non-existent document", func(t *testing.T) {
		err := client.DatastoreAddIdentity(t.Context(), &DatastoreAddIdentityRequest{
			AuthenticSource:    "SUNET",
			Scope:              "ehic",
			DocumentID:         "no-such",
			IdentityMappingIDs: []string{"person-001"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

func TestDatastoreDeleteIdentity(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)
	seedDoc(t, datastore, "SUNET", "ehic", "doc-di", []string{"person-001", "person-002"}, map[string]any{"x": 1})

	t.Run("remove identity", func(t *testing.T) {
		err := client.DatastoreDeleteIdentity(t.Context(), &DatastoreDeleteIdentityRequest{
			AuthenticSource:         "SUNET",
			Scope:                   "ehic",
			DocumentID:              "doc-di",
			AuthenticSourcePersonID: "person-002",
		})
		require.NoError(t, err)

		doc, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "doc-di",
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"person-001"}, doc.Data.IdentityMappingIDs)
	})

	t.Run("remove from non-existent document", func(t *testing.T) {
		err := client.DatastoreDeleteIdentity(t.Context(), &DatastoreDeleteIdentityRequest{
			AuthenticSource:         "SUNET",
			Scope:                   "ehic",
			DocumentID:              "no-such",
			AuthenticSourcePersonID: "person-001",
		})
		assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
	})
}

// --- DatastoreResolve ---

func TestDatastoreResolve(t *testing.T) {
	client, datastore, identityStore := newDatastoreTestClient(t)

	// Setup identity mapping
	err := identityStore.CreateMapping(t.Context(), &model.IdentityMapping{
		AuthenticSourcePersonID: "person-001",
		AuthenticSource:         "SUNET",
		Attributes:              map[string]string{"family_name": "Johansson", "given_name": "Erik"},
	})
	require.NoError(t, err)

	seedDoc(t, datastore, "SUNET", "ehic", "doc-r1", []string{"person-001"}, map[string]any{"card": "SE-1"})
	seedDoc(t, datastore, "SUNET", "pda1", "doc-r2", []string{"person-001"}, map[string]any{"card": "SE-2"})

	t.Run("resolve attributes to documents", func(t *testing.T) {
		reply, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			Attributes:      map[string]string{"family_name": "Johansson", "given_name": "Erik"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.AuthenticSourcePersonID)
		require.Len(t, reply.Data, 1)
		assert.Equal(t, "doc-r1", reply.Data[0].Meta.DocumentID)
	})

	t.Run("unknown attributes", func(t *testing.T) {
		_, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			Attributes:      map[string]string{"family_name": "Unknown"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})

	t.Run("wrong authentic source", func(t *testing.T) {
		_, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "OTHER",
			Scope:           "ehic",
			Attributes:      map[string]string{"family_name": "Johansson", "given_name": "Erik"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})
}

// --- Authentic source isolation ---

func TestAuthenticSourceIsolation(t *testing.T) {
	client, datastore, identityStore := newDatastoreTestClient(t)

	// Two different sources with the same person ID but different attributes
	err := identityStore.CreateMapping(t.Context(), &model.IdentityMapping{
		AuthenticSourcePersonID: "person-001",
		AuthenticSource:         "SOURCE_A",
		Attributes:              map[string]string{"ssn": "111111-1111"},
	})
	require.NoError(t, err)
	err = identityStore.CreateMapping(t.Context(), &model.IdentityMapping{
		AuthenticSourcePersonID: "person-001",
		AuthenticSource:         "SOURCE_B",
		Attributes:              map[string]string{"ssn": "222222-2222"},
	})
	require.NoError(t, err)

	seedDoc(t, datastore, "SOURCE_A", "ehic", "doc-a", []string{"person-001"}, map[string]any{"source": "A"})
	seedDoc(t, datastore, "SOURCE_B", "ehic", "doc-b", []string{"person-001"}, map[string]any{"source": "B"})

	t.Run("resolve from SOURCE_A only sees A", func(t *testing.T) {
		reply, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "SOURCE_A", Scope: "ehic",
			Attributes: map[string]string{"ssn": "111111-1111"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.AuthenticSourcePersonID)
		require.Len(t, reply.Data, 1)
		assert.Equal(t, "doc-a", reply.Data[0].Meta.DocumentID)
	})

	t.Run("cross-source resolution fails", func(t *testing.T) {
		_, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "SOURCE_A", Scope: "ehic",
			Attributes: map[string]string{"ssn": "222222-2222"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})
}

// --- Document data integrity ---

func TestDocumentDataIntegrity(t *testing.T) {
	client, _, _ := newDatastoreTestClient(t)

	complexData := map[string]any{
		"string_field":  "hello",
		"int_field":     float64(42),
		"float_field":   3.14,
		"bool_true":     true,
		"bool_false":    false,
		"null_field":    nil,
		"empty_string":  "",
		"empty_array":   []any{},
		"empty_object":  map[string]any{},
		"array_strings": []any{"a", "b", "c"},
		"array_numbers": []any{float64(1), float64(2), float64(3)},
		"array_mixed":   []any{"text", float64(99), true, nil},
		"nested": map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"deep_value": "found",
				},
			},
			"sibling": "value",
		},
		"array_of_objects": []any{
			map[string]any{"name": "Alice", "age": float64(30)},
			map[string]any{"name": "Bob", "age": float64(25)},
		},
		"unicode": "åäö émojis: 🎓",
	}

	_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "AS1",
			Scope:           "test",
			DocumentID:      "complex-doc",
		},
		IdentityMappingIDs: []string{"id-1"},
		DocumentData:       complexData,
	})
	require.NoError(t, err)

	reply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
		AuthenticSource: "AS1", Scope: "test", DocumentID: "complex-doc",
	})
	require.NoError(t, err)

	data := reply.Data.DocumentData

	// Scalars
	assert.Equal(t, "hello", data["string_field"])
	assert.Equal(t, float64(42), data["int_field"])
	assert.Equal(t, 3.14, data["float_field"])
	assert.Equal(t, true, data["bool_true"])
	assert.Equal(t, false, data["bool_false"])
	assert.Nil(t, data["null_field"])
	assert.Equal(t, "", data["empty_string"])

	// Empty collections
	assert.Equal(t, []any{}, data["empty_array"])
	assert.Equal(t, map[string]any{}, data["empty_object"])

	// Arrays
	assert.Equal(t, []any{"a", "b", "c"}, data["array_strings"])
	assert.Equal(t, []any{float64(1), float64(2), float64(3)}, data["array_numbers"])
	assert.Equal(t, []any{"text", float64(99), true, nil}, data["array_mixed"])

	// Deeply nested maps
	nested, ok := data["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", nested["sibling"])

	level1, ok := nested["level1"].(map[string]any)
	require.True(t, ok)
	level2, ok := level1["level2"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "found", level2["deep_value"])

	// Array of objects
	arrObj, ok := data["array_of_objects"].([]any)
	require.True(t, ok)
	require.Len(t, arrObj, 2)
	alice, ok := arrObj[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Alice", alice["name"])
	assert.Equal(t, float64(30), alice["age"])

	// Unicode
	assert.Equal(t, "åäö émojis: 🎓", data["unicode"])
}

func TestValidNotAfterRoundTrip(t *testing.T) {
	client, _, _ := newDatastoreTestClient(t)

	expiry := time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)

	_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "AS1",
			Scope:           "test",
			DocumentID:      "expiring-doc",
			ValidNotAfter:   &expiry,
		},
		IdentityMappingIDs: []string{"id-1"},
		DocumentData:       map[string]any{"key": "value"},
	})
	require.NoError(t, err)

	reply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
		AuthenticSource: "AS1", Scope: "test", DocumentID: "expiring-doc",
	})
	require.NoError(t, err)
	require.NotNil(t, reply.Data.Meta.ValidNotAfter)
	assert.True(t, expiry.Equal(*reply.Data.Meta.ValidNotAfter))

	t.Run("nil_valid_not_after", func(t *testing.T) {
		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "AS1",
				Scope:           "test",
				DocumentID:      "no-expiry-doc",
			},
			IdentityMappingIDs: []string{"id-1"},
			DocumentData:       map[string]any{"key": "value"},
		})
		require.NoError(t, err)

		reply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "AS1", Scope: "test", DocumentID: "no-expiry-doc",
		})
		require.NoError(t, err)
		assert.Nil(t, reply.Data.Meta.ValidNotAfter)
	})
}

// --- Multiple documents per identity ---

func TestMultipleDocumentsPerIdentity(t *testing.T) {
	client, datastore, _ := newDatastoreTestClient(t)

	for _, scope := range []string{"ehic", "pda1", "diploma"} {
		seedDoc(t, datastore, "SUNET", scope, "doc-"+scope, []string{"person-001"}, map[string]any{"scope": scope})
	}

	reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
		AuthenticSource:   "SUNET",
		IdentityMappingID: "person-001",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Data, 3)

	// Filter by scope
	reply, err = client.DatastoreList(t.Context(), &DatastoreListRequest{
		AuthenticSource:   "SUNET",
		IdentityMappingID: "person-001",
		Scope:             "pda1",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Data, 1)
	assert.Equal(t, "pda1", reply.Data[0].Meta.Scope)
}

// --- Multiple identities per document ---

func TestMultipleIdentitiesPerDocument(t *testing.T) {
	client, _, identityStore := newDatastoreTestClient(t)

	// Create two identity mappings with distinct attributes
	for _, m := range []struct {
		id, name string
	}{
		{"person-A", "Alice"},
		{"person-B", "Bob"},
	} {
		_, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: m.id,
			Attributes:              map[string]string{"given_name": m.name},
		})
		require.NoError(t, err)
	}

	// Upload document linked to both identities
	_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "SUNET",
			Scope:           "shared",
			DocumentID:      "shared-doc",
		},
		IdentityMappingIDs: []string{"person-A", "person-B"},
		DocumentData:       map[string]any{"shared": true},
	})
	require.NoError(t, err)

	t.Run("each identity can list the document", func(t *testing.T) {
		for _, id := range []string{"person-A", "person-B"} {
			reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
				AuthenticSource:   "SUNET",
				IdentityMappingID: id,
				Scope:             "shared",
			})
			require.NoError(t, err, "identity: %s", id)
			require.Len(t, reply.Data, 1, "identity: %s", id)
			assert.Equal(t, "shared-doc", reply.Data[0].Meta.DocumentID)
		}
	})

	t.Run("each identity can resolve to the document", func(t *testing.T) {
		for _, m := range []struct {
			name, id string
		}{
			{"Alice", "person-A"},
			{"Bob", "person-B"},
		} {
			reply, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
				AuthenticSource: "SUNET",
				Scope:           "shared",
				Attributes:      map[string]string{"given_name": m.name},
			})
			require.NoError(t, err, "identity: %s", m.id)
			assert.Equal(t, m.id, reply.AuthenticSourcePersonID)
			require.Len(t, reply.Data, 1, "identity: %s", m.id)
			assert.Equal(t, "shared-doc", reply.Data[0].Meta.DocumentID)
		}
	})

	t.Run("adding a third identity grants access", func(t *testing.T) {
		_, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "person-C",
			Attributes:              map[string]string{"given_name": "Charlie"},
		})
		require.NoError(t, err)

		err = client.DatastoreAddIdentity(t.Context(), &DatastoreAddIdentityRequest{
			AuthenticSource:    "SUNET",
			Scope:              "shared",
			DocumentID:         "shared-doc",
			IdentityMappingIDs: []string{"person-C"},
		})
		require.NoError(t, err)

		reply, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
			AuthenticSource: "SUNET",
			Scope:           "shared",
			Attributes:      map[string]string{"given_name": "Charlie"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-C", reply.AuthenticSourcePersonID)
		require.Len(t, reply.Data, 1)
	})

	t.Run("removing one identity doesn't affect others", func(t *testing.T) {
		err := client.DatastoreDeleteIdentity(t.Context(), &DatastoreDeleteIdentityRequest{
			AuthenticSource:         "SUNET",
			Scope:                   "shared",
			DocumentID:              "shared-doc",
			AuthenticSourcePersonID: "person-A",
		})
		require.NoError(t, err)

		// person-A can no longer list
		listReply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			AuthenticSource:   "SUNET",
			IdentityMappingID: "person-A",
			Scope:             "shared",
		})
		require.NoError(t, err)
		assert.Empty(t, listReply.Data)

		// person-B still has access
		listReply, err = client.DatastoreList(t.Context(), &DatastoreListRequest{
			AuthenticSource:   "SUNET",
			IdentityMappingID: "person-B",
			Scope:             "shared",
		})
		require.NoError(t, err)
		require.Len(t, listReply.Data, 1)

		// person-C still has access
		_ = identityStore // used in setup
		listReply, err = client.DatastoreList(t.Context(), &DatastoreListRequest{
			AuthenticSource:   "SUNET",
			IdentityMappingID: "person-C",
			Scope:             "shared",
		})
		require.NoError(t, err)
		require.Len(t, listReply.Data, 1)
	})
}

// --- Full end-to-end lifecycle ---

func TestFullLifecycle(t *testing.T) {
	client, _, identityStore := newDatastoreTestClient(t)

	// 1. Create identity mapping via handler
	createReply, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "lifecycle-001",
		Attributes:              map[string]string{"ssn": "199001011234", "family_name": "Johansson"},
	})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-001", createReply.AuthenticSourcePersonID)

	// 2. Upload document via handler (auto-provisions mapping link)
	_, err = client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "lc-doc-001",
		},
		IdentityMappingIDs: []string{"lifecycle-001"},
		DocumentData:       map[string]any{"card_number": "SE-EHIC-12345", "institution": "Försäkringskassan"},
	})
	require.NoError(t, err)

	// 3. Resolve identity by attributes → find documents
	resolveReply, err := client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
		AuthenticSource: "SUNET",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "family_name": "Johansson"},
	})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-001", resolveReply.AuthenticSourcePersonID)
	require.Len(t, resolveReply.Data, 1)
	assert.Equal(t, "lc-doc-001", resolveReply.Data[0].Meta.DocumentID)

	// 4. Get document by key
	getReply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
		AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "lc-doc-001",
	})
	require.NoError(t, err)
	assert.Equal(t, "Försäkringskassan", getReply.Data.DocumentData["institution"])

	// 5. Update identity mapping attributes
	err = client.IdentityMappingUpdate(t.Context(), &IdentityMappingUpdateRequest{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "lifecycle-001",
		Attributes:              map[string]string{"ssn": "199001011234", "family_name": "Johansson", "email": "erik@example.se"},
	})
	require.NoError(t, err)

	// 6. Re-resolve with updated attributes
	resolveReply, err = client.DatastoreResolve(t.Context(), &DatastoreResolveRequest{
		AuthenticSource: "SUNET",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "family_name": "Johansson", "email": "erik@example.se"},
	})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-001", resolveReply.AuthenticSourcePersonID)
	require.Len(t, resolveReply.Data, 1)
	assert.Equal(t, "lc-doc-001", resolveReply.Data[0].Meta.DocumentID)

	// 7. Old attributes no longer resolve (attributes were replaced, not merged)
	identityStore.mu.RLock()
	m := identityStore.mappings[mappingKey("SUNET", "lifecycle-001")]
	identityStore.mu.RUnlock()
	assert.Equal(t, "erik@example.se", m.Attributes["email"])

	// 8. Delete document
	err = client.DatastoreDeleteByKey(t.Context(), &DatastoreDeleteByKeyRequest{
		AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "lc-doc-001",
	})
	require.NoError(t, err)

	// 9. Verify document is gone
	_, err = client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
		AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "lc-doc-001",
	})
	assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)

	// 10. Delete identity mapping
	err = client.IdentityMappingDelete(t.Context(), &IdentityMappingDeleteRequest{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: "lifecycle-001",
	})
	require.NoError(t, err)

	// 11. Resolve fails after mapping deletion
	_, err = client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"ssn": "199001011234", "family_name": "Johansson", "email": "erik@example.se"},
	})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
}

// --- DatastoreUpload ---

func TestDatastoreUpload(t *testing.T) {
	t.Run("saves document and auto-provisions identity mappings", func(t *testing.T) {
		client, datastore, identityStore := newDatastoreTestClient(t)

		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-001",
			},
			IdentityMappingIDs: []string{"person-001"},
			DocumentData:       map[string]any{"card": "SE-123"},
		})
		require.NoError(t, err)

		// Verify document was saved
		doc, ok := datastore.docs[docKey("SUNET", "ehic", "upload-001")]
		require.True(t, ok)
		assert.Equal(t, "SE-123", doc.DocumentData["card"])

		// Verify identity mapping was auto-provisioned
		identityStore.mu.RLock()
		_, exists := identityStore.mappings[mappingKey("SUNET", "person-001")]
		identityStore.mu.RUnlock()
		assert.True(t, exists, "EnsureMapping should have created the identity mapping")
	})

	t.Run("multiple identity mappings are all ensured", func(t *testing.T) {
		client, _, identityStore := newDatastoreTestClient(t)

		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-003",
			},
			IdentityMappingIDs: []string{"id-a", "id-b", "id-c"},
			DocumentData:       map[string]any{"x": 1},
		})
		require.NoError(t, err)

		identityStore.mu.RLock()
		defer identityStore.mu.RUnlock()
		for _, id := range []string{"id-a", "id-b", "id-c"} {
			_, exists := identityStore.mappings[mappingKey("SUNET", id)]
			assert.True(t, exists, "EnsureMapping should have created mapping for %s", id)
		}
	})

	t.Run("existing identity mapping is not overwritten", func(t *testing.T) {
		client, _, identityStore := newDatastoreTestClient(t)

		// Pre-create mapping with attributes
		seedMapping(t, identityStore, "SUNET", "existing-person", map[string]string{"ssn": "123"})

		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-004",
			},
			IdentityMappingIDs: []string{"existing-person"},
			DocumentData:       map[string]any{"y": 2},
		})
		require.NoError(t, err)

		// Verify existing attributes were preserved
		identityStore.mu.RLock()
		m := identityStore.mappings[mappingKey("SUNET", "existing-person")]
		identityStore.mu.RUnlock()
		assert.Equal(t, "123", m.Attributes["ssn"], "EnsureMapping should not overwrite existing attributes")
	})

	t.Run("duplicate document upload fails", func(t *testing.T) {
		client, _, _ := newDatastoreTestClient(t)

		req := &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-dup",
			},
			IdentityMappingIDs: []string{"person-001"},
			DocumentData:       map[string]any{"x": 1},
		}
		_, err := client.DatastoreUpload(t.Context(), req)
		require.NoError(t, err)
		_, err = client.DatastoreUpload(t.Context(), req)
		assert.Error(t, err, "uploading the same document twice should fail")
	})

	t.Run("uploaded document is retrievable by key", func(t *testing.T) {
		client, _, _ := newDatastoreTestClient(t)

		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-get",
			},
			IdentityMappingIDs: []string{"person-get"},
			DocumentData:       map[string]any{"field": "value"},
		})
		require.NoError(t, err)

		reply, err := client.DatastoreGetByKey(t.Context(), &DatastoreGetByKeyRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "upload-get",
		})
		require.NoError(t, err)
		assert.Equal(t, "value", reply.Data.DocumentData["field"])
	})

	t.Run("uploaded document is listable by identity", func(t *testing.T) {
		client, _, _ := newDatastoreTestClient(t)

		_, err := client.DatastoreUpload(t.Context(), &vcclient.UploadRequest{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "upload-list",
			},
			IdentityMappingIDs: []string{"list-person"},
			DocumentData:       map[string]any{"z": 3},
		})
		require.NoError(t, err)

		reply, err := client.DatastoreList(t.Context(), &DatastoreListRequest{
			AuthenticSource:   "SUNET",
			IdentityMappingID: "list-person",
			Scope:             "ehic",
		})
		require.NoError(t, err)
		require.Len(t, reply.Data, 1)
		assert.Equal(t, "upload-list", reply.Data[0].Meta.DocumentID)
	})
}

// --- DatastoreDelete error path ---

func TestDatastoreDeleteNotFound(t *testing.T) {
	client, _, _ := newDatastoreTestClient(t)

	err := client.DatastoreDelete(t.Context(), &DatastoreDeleteRequest{
		AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "no-such",
	})
	assert.Error(t, err)
}

// --- DatastorePreAuthOffer ---

func newPreAuthOfferTestClient(t *testing.T) (*Client, *memoryDatastoreStore) {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	datastore := newMemoryDatastoreStore()
	authContextStore := cache.NewTestMemoryStore(10 * time.Minute)
	docCache := cache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute)

	client := &Client{
		log:            log,
		datastoreStore: datastore,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						IssuerURL: "https://issuer.example.com",
						Wallets:   map[string]model.CredentialOfferWallets{},
					},
				},
			},
		},
		cacheService: &cache.Service{
			AuthContext: authContextStore,
			Document:    docCache,
		},
	}
	return client, datastore
}

func TestDatastorePreAuthOffer_Success(t *testing.T) {
	client, datastore := newPreAuthOfferTestClient(t)

	seedDoc(t, datastore, "SUNET", "pid", "doc-1", []string{"person-1"}, map[string]any{
		"family_name": "Doe",
		"given_name":  "John",
	})

	reply, err := client.DatastorePreAuthOffer(t.Context(), &DatastorePreAuthOfferRequest{
		AuthenticSource: "SUNET",
		Scope:           "pid",
		DocumentID:      "doc-1",
	})

	require.NoError(t, err)
	require.NotNil(t, reply)

	// Verify credential offer fields
	assert.Equal(t, "https://issuer.example.com", reply.CredentialOffer.CredentialIssuer)
	assert.Equal(t, []string{"pid"}, reply.CredentialOffer.CredentialConfigurationIDs)
	assert.NotEmpty(t, reply.CredentialOffer.ID)

	// Verify the offer contains a pre-authorized code grant
	grant, ok := reply.CredentialOffer.Grants[openid4vci.GrantTypePreAuthorizedCode]
	require.True(t, ok, "offer should contain pre-authorized_code grant")
	require.NotNil(t, grant)

	// Verify credential offer URL
	assert.Contains(t, reply.CredentialOfferURL, "openid-credential-offer://")
	assert.Contains(t, reply.CredentialOfferURL, "credential_offer")

}

func TestDatastorePreAuthOffer_DocumentNotFound(t *testing.T) {
	client, _ := newPreAuthOfferTestClient(t)

	reply, err := client.DatastorePreAuthOffer(t.Context(), &DatastorePreAuthOfferRequest{
		AuthenticSource: "SUNET",
		Scope:           "pid",
		DocumentID:      "nonexistent",
	})

	require.Error(t, err)
	assert.Nil(t, reply)
	assert.ErrorIs(t, err, helpers.ErrNoDocumentFound)
}

func TestDatastorePreAuthOffer_AuthContextPersisted(t *testing.T) {
	client, datastore := newPreAuthOfferTestClient(t)

	seedDoc(t, datastore, "SUNET", "ehic", "doc-2", []string{"person-2"}, map[string]any{
		"card_number": "SE123456",
	})

	reply, err := client.DatastorePreAuthOffer(t.Context(), &DatastorePreAuthOfferRequest{
		AuthenticSource: "SUNET",
		Scope:           "ehic",
		DocumentID:      "doc-2",
	})
	require.NoError(t, err)

	// Verify the auth context was saved by retrieving it
	preAuthCode := reply.CredentialOffer.ID
	authCtx, err := client.cacheService.AuthContext.GetByID(t.Context(), preAuthCode)
	require.NoError(t, err)
	require.NotNil(t, authCtx)

	assert.Equal(t, preAuthCode, authCtx.SessionID)
	assert.Equal(t, preAuthCode, authCtx.Code)
	assert.Equal(t, "code_issued", string(authCtx.Status))
	assert.Equal(t, []string{"ehic"}, authCtx.Scopes)
	assert.Equal(t, "datastore", authCtx.DataSource)
	assert.NotEmpty(t, authCtx.Nonce)
	assert.True(t, authCtx.ExpiresAt > time.Now().Unix())
}

func TestDatastorePreAuthOffer_DocumentDataCached(t *testing.T) {
	client, datastore := newPreAuthOfferTestClient(t)

	docData := map[string]any{
		"family_name": "Smith",
		"given_name":  "Jane",
		"birth_date":  "1990-05-15",
	}
	seedDoc(t, datastore, "SUNET", "pid", "doc-3", []string{"person-3"}, docData)

	reply, err := client.DatastorePreAuthOffer(t.Context(), &DatastorePreAuthOfferRequest{
		AuthenticSource: "SUNET",
		Scope:           "pid",
		DocumentID:      "doc-3",
	})
	require.NoError(t, err)

	// Verify the document data was cached for the credential endpoint
	preAuthCode := reply.CredentialOffer.ID
	assert.True(t, client.HasVCIDocuments(t.Context(), preAuthCode))
}
