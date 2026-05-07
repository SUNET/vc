package apiv1

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
)

// memoryDatastoreStore is an in-memory implementation of db.DatastoreStore for testing.
type memoryDatastoreStore struct {
	mu   sync.RWMutex
	docs map[string]*model.CompleteDocument // key: "authentic_source|scope|document_id"
}

func newMemoryDatastoreStore() *memoryDatastoreStore {
	return &memoryDatastoreStore{
		docs: make(map[string]*model.CompleteDocument),
	}
}

func docKey(authenticSource, scope, documentID string) string {
	return fmt.Sprintf("%s|%s|%s", authenticSource, scope, documentID)
}

func (m *memoryDatastoreStore) Save(_ context.Context, doc *model.CompleteDocument) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID)
	if _, exists := m.docs[key]; exists {
		return fmt.Errorf("document already exists: %s", key)
	}
	m.docs[key] = doc
	return nil
}

func (m *memoryDatastoreStore) Replace(_ context.Context, doc *model.CompleteDocument) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID)
	m.docs[key] = doc
	return nil
}

func (m *memoryDatastoreStore) Get(_ context.Context, meta *model.MetaData) (*model.Document, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := docKey(meta.AuthenticSource, meta.Scope, meta.DocumentID)
	doc, ok := m.docs[key]
	if !ok {
		return nil, helpers.ErrNoDocumentFound
	}
	return &model.Document{
		Meta:         doc.Meta,
		DocumentData: doc.DocumentData,
	}, nil
}

func (m *memoryDatastoreStore) GetByKey(_ context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := docKey(authenticSource, scope, documentID)
	doc, ok := m.docs[key]
	if !ok {
		return nil, helpers.ErrNoDocumentFound
	}
	return doc, nil
}

func (m *memoryDatastoreStore) Delete(_ context.Context, meta *model.MetaData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(meta.AuthenticSource, meta.Scope, meta.DocumentID)
	if _, exists := m.docs[key]; !exists {
		return helpers.ErrNoDocumentFound
	}
	delete(m.docs, key)
	return nil
}

func (m *memoryDatastoreStore) DeleteByKey(_ context.Context, authenticSource, scope, documentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(authenticSource, scope, documentID)
	if _, exists := m.docs[key]; !exists {
		return helpers.ErrNoDocumentFound
	}
	delete(m.docs, key)
	return nil
}

func (m *memoryDatastoreStore) GetByIdentity(_ context.Context, scope, identityMappingID string) (map[string]*model.CompleteDocument, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*model.CompleteDocument)
	for _, doc := range m.docs {
		if doc.Meta.Scope != scope {
			continue
		}
		if slices.Contains(doc.IdentityMappingIDs, identityMappingID) {
			result[doc.Meta.AuthenticSource] = doc
		}
	}
	return result, nil
}

func (m *memoryDatastoreStore) List(_ context.Context, query *db.ListQuery) ([]*model.DocumentList, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*model.DocumentList
	for _, doc := range m.docs {
		if query.AuthenticSource != "" && doc.Meta.AuthenticSource != query.AuthenticSource {
			continue
		}
		if query.Scope != "" && doc.Meta.Scope != query.Scope {
			continue
		}
		if !slices.Contains(doc.IdentityMappingIDs, query.IdentityMappingID) {
			continue
		}
		result = append(result, &model.DocumentList{
			Meta: doc.Meta,
		})
	}
	return result, nil
}

func (m *memoryDatastoreStore) AddIdentity(_ context.Context, query *db.AddIdentityQuery) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(query.AuthenticSource, query.Scope, query.DocumentID)
	doc, ok := m.docs[key]
	if !ok {
		return helpers.ErrNoDocumentFound
	}
	for _, newID := range query.IdentityMappingIDs {
		if !slices.Contains(doc.IdentityMappingIDs, newID) {
			doc.IdentityMappingIDs = append(doc.IdentityMappingIDs, newID)
		}
	}
	return nil
}

func (m *memoryDatastoreStore) DeleteIdentity(_ context.Context, query *db.DeleteIdentityQuery) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := docKey(query.AuthenticSource, query.Scope, query.DocumentID)
	doc, ok := m.docs[key]
	if !ok {
		return helpers.ErrNoDocumentFound
	}
	filtered := make([]string, 0, len(doc.IdentityMappingIDs))
	for _, id := range doc.IdentityMappingIDs {
		if id != query.AuthenticSourcePersonID {
			filtered = append(filtered, id)
		}
	}
	doc.IdentityMappingIDs = filtered
	return nil
}

func (m *memoryDatastoreStore) Search(_ context.Context, _ *db.SearchDocumentsQuery) ([]*model.CompleteDocument, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*model.CompleteDocument
	for _, doc := range m.docs {
		result = append(result, doc)
	}
	return result, nil
}

// memoryIdentityMappingStore is an in-memory implementation of db.IdentityMappingStore for testing.
type memoryIdentityMappingStore struct {
	mu       sync.RWMutex
	mappings map[string]*model.IdentityMapping // key: "authentic_source|authentic_source_person_id"
}

func newMemoryIdentityMappingStore() *memoryIdentityMappingStore {
	return &memoryIdentityMappingStore{
		mappings: make(map[string]*model.IdentityMapping),
	}
}

func mappingKey(authenticSource, personID string) string {
	return fmt.Sprintf("%s|%s", authenticSource, personID)
}

func (m *memoryIdentityMappingStore) CreateMapping(_ context.Context, mapping *model.IdentityMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := mappingKey(mapping.AuthenticSource, mapping.AuthenticSourcePersonID)
	if _, exists := m.mappings[key]; exists {
		return fmt.Errorf("mapping already exists: %s", key)
	}
	m.mappings[key] = mapping
	return nil
}

func (m *memoryIdentityMappingStore) EnsureMapping(_ context.Context, mapping *model.IdentityMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := mappingKey(mapping.AuthenticSource, mapping.AuthenticSourcePersonID)
	if _, exists := m.mappings[key]; !exists {
		m.mappings[key] = mapping
	}
	return nil
}

func (m *memoryIdentityMappingStore) ResolveMapping(_ context.Context, query *db.ResolveMappingQuery) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, mapping := range m.mappings {
		if query.AuthenticSource != "" && mapping.AuthenticSource != query.AuthenticSource {
			continue
		}
		if matchAttributes(mapping.Attributes, query.Attributes) {
			return mapping.AuthenticSourcePersonID, nil
		}
	}
	return "", helpers.ErrNoIdentityFound
}

func matchAttributes(stored map[string]string, query map[string]string) bool {
	if len(query) == 0 {
		return false
	}
	for key, val := range query {
		storedVal, ok := stored[key]
		if !ok || storedVal != val {
			return false
		}
	}
	return true
}

func (m *memoryIdentityMappingStore) UpdateMapping(_ context.Context, mapping *model.IdentityMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := mappingKey(mapping.AuthenticSource, mapping.AuthenticSourcePersonID)
	existing, ok := m.mappings[key]
	if !ok {
		return helpers.ErrNoIdentityFound
	}
	existing.Attributes = mapping.Attributes
	return nil
}

func (m *memoryIdentityMappingStore) DeleteMapping(_ context.Context, query *db.DeleteMappingQuery) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := mappingKey(query.AuthenticSource, query.AuthenticSourcePersonID)
	if _, exists := m.mappings[key]; !exists {
		return helpers.ErrNoIdentityFound
	}
	delete(m.mappings, key)
	return nil
}

func (m *memoryIdentityMappingStore) SearchMappings(_ context.Context, _ *db.SearchMappingsQuery) ([]*model.IdentityMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*model.IdentityMapping
	for _, mapping := range m.mappings {
		result = append(result, mapping)
	}
	return result, nil
}

// memoryCredentialOfferStore is an in-memory implementation of db.CredentialOfferStore for testing.
type memoryCredentialOfferStore struct {
	mu    sync.RWMutex
	offers map[string]*db.CredentialOfferDocument
}

func newMemoryCredentialOfferStore() *memoryCredentialOfferStore {
	return &memoryCredentialOfferStore{
		offers: make(map[string]*db.CredentialOfferDocument),
	}
}

func (m *memoryCredentialOfferStore) Save(_ context.Context, doc *db.CredentialOfferDocument) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.offers[doc.UUID] = doc
	return nil
}

func (m *memoryCredentialOfferStore) Get(_ context.Context, uuid string) (*db.CredentialOfferDocument, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.offers[uuid]
	if !ok {
		return nil, fmt.Errorf("credential offer not found: %s", uuid)
	}
	return doc, nil
}

func (m *memoryCredentialOfferStore) Delete(_ context.Context, uuid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.offers, uuid)
	return nil
}
