package db

import (
	"context"

	"github.com/SUNET/vc/pkg/model"
)

// CredentialOfferStore defines the interface for credential offer operations
type CredentialOfferStore interface {
	Save(ctx context.Context, doc *CredentialOfferDocument) error
	Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error)
	Delete(ctx context.Context, uuid string) error
}

// DatastoreStore defines the interface for datastore operations
type DatastoreStore interface {
	// Count returns the (possibly approximate) number of documents in the datastore.
	Count(ctx context.Context) (int64, error)
	Save(ctx context.Context, doc *model.CompleteDocument) error
	SaveMany(ctx context.Context, docs []*model.CompleteDocument) error
	AddIdentity(ctx context.Context, query *AddIdentityQuery) error
	DeleteIdentity(ctx context.Context, query *DeleteIdentityQuery) error
	Delete(ctx context.Context, doc *model.MetaData) error
	Get(ctx context.Context, meta *model.MetaData) (*model.Document, error)
	GetByIdentity(ctx context.Context, scope, identityMappingID string) (map[string]*model.CompleteDocument, error)
	List(ctx context.Context, query *ListQuery) ([]*model.DocumentList, error)
	Replace(ctx context.Context, doc *model.CompleteDocument) error
	GetByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error)
	DeleteByKey(ctx context.Context, authenticSource, scope, documentID string) error
	Search(ctx context.Context, query *SearchDocumentsQuery) ([]*model.CompleteDocument, error)
	ListAuthenticSources(ctx context.Context) ([]string, error)
}

// IdentityMappingStore defines the interface for identity mapping operations
type IdentityMappingStore interface {
	// Count returns the (possibly approximate) number of identity mappings.
	Count(ctx context.Context) (int64, error)
	CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	CreateMappings(ctx context.Context, mappings []*model.IdentityMapping) error
	EnsureMapping(ctx context.Context, mapping *model.IdentityMapping) error
	ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error)
	UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error
	SearchMappings(ctx context.Context, query *SearchMappingsQuery) ([]*model.IdentityMapping, error)
}

// DynamicRegistrationStore defines the interface for OIDC dynamic client registration operations
type DynamicRegistrationStore interface {
	Save(ctx context.Context, creds *DynamicRegistrationCredentials) error
	Get(ctx context.Context) (*DynamicRegistrationCredentials, error)
}

// Ensure concrete types implement the interfaces
var (
	_ CredentialOfferStore     = (*CredentialOfferColl)(nil)
	_ DatastoreStore           = (*DatastoreColl)(nil)
	_ IdentityMappingStore     = (*IdentityMappingsColl)(nil)
	_ DynamicRegistrationStore = (*DynamicRegistrationColl)(nil)
)
