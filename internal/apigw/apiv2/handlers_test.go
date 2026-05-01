package apiv2

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDatastoreV2Store implements db.DatastoreV2Store for testing.
type mockDatastoreV2Store struct {
	mappings  map[string]*model.IdentityMapping // key: authentic_source + identifier
	documents map[string]*model.V2Document      // key: authentic_source + scope + document_id
}

func newMockStore() *mockDatastoreV2Store {
	return &mockDatastoreV2Store{
		mappings:  make(map[string]*model.IdentityMapping),
		documents: make(map[string]*model.V2Document),
	}
}

func mappingKey(authenticSource, identifier string) string {
	return authenticSource + "|" + identifier
}

func docKey(authenticSource, scope, documentID string) string {
	return authenticSource + "|" + scope + "|" + documentID
}

func (m *mockDatastoreV2Store) CreateIdentityMapping(_ context.Context, mapping *model.IdentityMapping) (string, error) {
	if mapping.Identifier == "" {
		mapping.Identifier = "auto-generated-uuid"
	}
	m.mappings[mappingKey(mapping.AuthenticSource, mapping.Identifier)] = mapping
	return mapping.Identifier, nil
}

func (m *mockDatastoreV2Store) GetIdentityMapping(_ context.Context, authenticSource string, attributes map[string]string) (string, error) {
	for _, mapping := range m.mappings {
		if mapping.AuthenticSource != authenticSource {
			continue
		}
		if mapsEqual(mapping.Attributes, attributes) {
			return mapping.Identifier, nil
		}
	}
	return "", assert.AnError
}

func (m *mockDatastoreV2Store) UpdateIdentityMapping(_ context.Context, authenticSource, identifier string, attributes map[string]string) error {
	key := mappingKey(authenticSource, identifier)
	if _, ok := m.mappings[key]; !ok {
		return assert.AnError
	}
	m.mappings[key].Attributes = attributes
	return nil
}

func (m *mockDatastoreV2Store) DeleteIdentityMapping(_ context.Context, authenticSource, identifier string) error {
	key := mappingKey(authenticSource, identifier)
	if _, ok := m.mappings[key]; !ok {
		return assert.AnError
	}
	delete(m.mappings, key)
	return nil
}

func (m *mockDatastoreV2Store) SaveDocument(_ context.Context, doc *model.V2Document) error {
	if doc.Meta.DocumentID == "" {
		doc.Meta.DocumentID = "auto-generated-doc-uuid"
	}
	m.documents[docKey(doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID)] = doc
	return nil
}

func (m *mockDatastoreV2Store) GetDocument(_ context.Context, authenticSource, scope, documentID string) (*model.V2Document, error) {
	key := docKey(authenticSource, scope, documentID)
	if doc, ok := m.documents[key]; ok {
		return doc, nil
	}
	return nil, assert.AnError
}

func (m *mockDatastoreV2Store) ListDocuments(_ context.Context, authenticSource, identifier, scope string) ([]*model.V2Document, error) {
	var results []*model.V2Document
	for _, doc := range m.documents {
		if doc.Meta.AuthenticSource != authenticSource {
			continue
		}
		if scope != "" && doc.Meta.Scope != scope {
			continue
		}
		for _, id := range doc.Identities {
			if id == identifier {
				results = append(results, doc)
				break
			}
		}
	}
	return results, nil
}

func (m *mockDatastoreV2Store) DeleteDocument(_ context.Context, authenticSource, scope, documentID string) error {
	key := docKey(authenticSource, scope, documentID)
	if _, ok := m.documents[key]; !ok {
		return assert.AnError
	}
	delete(m.documents, key)
	return nil
}

func (m *mockDatastoreV2Store) ResolveAndGetDocuments(ctx context.Context, authenticSource, scope string, attributes map[string]string) ([]*model.V2Document, error) {
	identifier, err := m.GetIdentityMapping(ctx, authenticSource, attributes)
	if err != nil {
		return nil, err
	}
	return m.ListDocuments(ctx, authenticSource, identifier, scope)
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func newTestClient(store *mockDatastoreV2Store) *Client {
	log, _ := logger.New("test", "", false)
	tracer, _ := trace.NewForTesting(context.Background(), "test", log)
	return &Client{
		datastoreStore: store,
		tracer:         tracer,
	}
}

func TestCreateIdentityMapping(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	t.Run("with explicit identifier", func(t *testing.T) {
		reply, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
			Attributes:      map[string]string{"ssn": "010101-0101"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.Identifier)
	})

	t.Run("with auto-generated identifier", func(t *testing.T) {
		reply, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"ssn": "020202-0202"},
		})
		require.NoError(t, err)
		assert.Equal(t, "auto-generated-uuid", reply.Identifier)
	})
}

func TestResolveIdentityMapping(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create a mapping first
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SUNET",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	t.Run("successful resolve", func(t *testing.T) {
		reply, err := client.ResolveIdentityMapping(ctx, &ResolveIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"ssn": "010101-0101"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.Identifier)
	})

	t.Run("unknown attributes", func(t *testing.T) {
		_, err := client.ResolveIdentityMapping(ctx, &ResolveIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"ssn": "999999-9999"},
		})
		assert.Error(t, err)
	})
}

func TestUpdateIdentityMapping(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create first
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SUNET",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	t.Run("update existing", func(t *testing.T) {
		err := client.UpdateIdentityMapping(ctx, &UpdateIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
			Attributes:      map[string]string{"ssn": "010101-0101", "nationality": "SE"},
		})
		require.NoError(t, err)

		// Verify it can be resolved with new attributes
		reply, err := client.ResolveIdentityMapping(ctx, &ResolveIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"ssn": "010101-0101", "nationality": "SE"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.Identifier)
	})

	t.Run("update non-existent", func(t *testing.T) {
		err := client.UpdateIdentityMapping(ctx, &UpdateIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Identifier:      "non-existent",
			Attributes:      map[string]string{"ssn": "010101-0101"},
		})
		assert.Error(t, err)
	})
}

func TestDeleteIdentityMapping(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create first
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SUNET",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	t.Run("delete existing", func(t *testing.T) {
		err := client.DeleteIdentityMapping(ctx, &DeleteIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
		})
		require.NoError(t, err)
	})

	t.Run("delete non-existent", func(t *testing.T) {
		err := client.DeleteIdentityMapping(ctx, &DeleteIdentityMappingRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
		})
		assert.Error(t, err)
	})
}

func TestUploadDocument(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	t.Run("with explicit document_id", func(t *testing.T) {
		reply, err := client.UploadDocument(ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "EHIC_DB_0001",
				Scope:           "ehic",
				DocumentID:      "doc-001",
			},
			Identities:   []string{"person-001"},
			DocumentData: map[string]any{"document_number": "123456"},
		})
		require.NoError(t, err)
		assert.Equal(t, "doc-001", reply.DocumentID)
	})

	t.Run("with auto-generated document_id", func(t *testing.T) {
		reply, err := client.UploadDocument(ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "EHIC_DB_0001",
				Scope:           "ehic",
			},
			Identities:   []string{"person-001"},
			DocumentData: map[string]any{"document_number": "789012"},
		})
		require.NoError(t, err)
		assert.Equal(t, "auto-generated-doc-uuid", reply.DocumentID)
	})
}

func TestGetDocument(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Upload first
	_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "EHIC_DB_0001",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"document_number": "123456"},
	})
	require.NoError(t, err)

	t.Run("existing document", func(t *testing.T) {
		reply, err := client.GetDocument(ctx, &GetDocumentRequest{
			AuthenticSource: "EHIC_DB_0001",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		})
		require.NoError(t, err)
		assert.Equal(t, "doc-001", reply.Document.Meta.DocumentID)
		assert.Equal(t, "123456", reply.Document.DocumentData["document_number"])
	})

	t.Run("non-existent document", func(t *testing.T) {
		_, err := client.GetDocument(ctx, &GetDocumentRequest{
			AuthenticSource: "EHIC_DB_0001",
			Scope:           "ehic",
			DocumentID:      "non-existent",
		})
		assert.Error(t, err)
	})
}

func TestListDocuments(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Upload two documents for same identifier
	_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"type": "ehic"},
	})
	require.NoError(t, err)

	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SUNET",
			Scope:           "pda1",
			DocumentID:      "doc-002",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"type": "pda1"},
	})
	require.NoError(t, err)

	t.Run("list all scopes", func(t *testing.T) {
		reply, err := client.ListDocuments(ctx, &ListDocumentsRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Documents, 2)
	})

	t.Run("filter by scope", func(t *testing.T) {
		reply, err := client.ListDocuments(ctx, &ListDocumentsRequest{
			AuthenticSource: "SUNET",
			Identifier:      "person-001",
			Scope:           "ehic",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Documents, 1)
		assert.Equal(t, "ehic", reply.Documents[0].Meta.Scope)
	})
}

func TestDeleteDocument(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Upload first
	_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"type": "ehic"},
	})
	require.NoError(t, err)

	t.Run("delete existing", func(t *testing.T) {
		err := client.DeleteDocument(ctx, &DeleteDocumentRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		})
		require.NoError(t, err)
	})

	t.Run("delete non-existent", func(t *testing.T) {
		err := client.DeleteDocument(ctx, &DeleteDocumentRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		})
		assert.Error(t, err)
	})
}

func TestResolveDocuments(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create mapping
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SUNET",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	// Upload document for that identifier
	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "doc-001",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"document_number": "123"},
	})
	require.NoError(t, err)

	t.Run("resolve and get", func(t *testing.T) {
		reply, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			Attributes:      map[string]string{"ssn": "010101-0101"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-001", reply.Identifier)
		assert.Len(t, reply.Documents, 1)
		assert.Equal(t, "doc-001", reply.Documents[0].Meta.DocumentID)
	})

	t.Run("resolve unknown identity", func(t *testing.T) {
		_, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			Attributes:      map[string]string{"ssn": "999999-9999"},
		})
		assert.Error(t, err)
	})
}
