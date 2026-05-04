package db

import (
	"context"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// CredentialOfferStore defines the interface for credential offer operations
type CredentialOfferStore interface {
	Save(ctx context.Context, doc *CredentialOfferDocument) error
	Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error)
	Delete(ctx context.Context, uuid string) error
}

// DatastoreStore defines the interface for datastore operations
type DatastoreStore interface {
	Save(ctx context.Context, doc *model.CompleteDocument) error
	AddDocumentIdentity(ctx context.Context, query *AddDocumentIdentityQuery) error
	DeleteDocumentIdentity(ctx context.Context, query *DeleteDocumentIdentityQuery) error
	Delete(ctx context.Context, doc *model.MetaData) error
	GetDocument(ctx context.Context, query *GetDocumentQuery) (*model.Document, error)
	GetDocumentsByClaims(ctx context.Context, scope string, identityClaims map[string]string) (map[string]*model.CompleteDocument, error)
	DocumentList(ctx context.Context, query *DocumentListQuery) ([]*model.DocumentList, error)
	GetQR(ctx context.Context, attr *model.MetaData) (*openid4vci.QR, error)
	Replace(ctx context.Context, doc *model.CompleteDocument) error
	SearchDocuments(ctx context.Context, query *SearchDocumentsQuery, limit int64, fields []string, sortFields map[string]int) ([]*model.CompleteDocument, bool, error)

	// Simplified document operations (new API)
	GetDocumentByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error)
	DeleteDocumentByKey(ctx context.Context, authenticSource, scope, documentID string) error
	ListDocumentsByIdentifier(ctx context.Context, identifier string) ([]*model.CompleteDocument, error)
}

// IdentityMappingStore defines the interface for identity mapping operations
type IdentityMappingStore interface {
	CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error)
	UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error
}

// Ensure concrete types implement the interfaces
var _ CredentialOfferStore = (*VCCredentialOfferColl)(nil)
var _ DatastoreStore = (*VCDatastoreColl)(nil)
var _ IdentityMappingStore = (*VCIdentityMappingsColl)(nil)
