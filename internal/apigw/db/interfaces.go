package db

import (
	"context"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// UsersStore defines the interface for user operations
type UsersStore interface {
	Save(ctx context.Context, doc *model.OAuthUsers) error
	GetUser(ctx context.Context, username string) (*model.OAuthUsers, error)
	GetHashedPassword(ctx context.Context, username string) (string, error)
}

// CredentialOfferStore defines the interface for credential offer operations
type CredentialOfferStore interface {
	Save(ctx context.Context, doc *CredentialOfferDocument) error
	Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error)
	Delete(ctx context.Context, uuid string) error
}

// DatastoreStore defines the interface for datastore operations
type DatastoreStore interface {
	Save(ctx context.Context, doc *model.CompleteDocument) error
	IDMapping(ctx context.Context, query *IDMappingQuery) (string, error)
	AddDocumentIdentity(ctx context.Context, query *AddDocumentIdentityQuery) error
	DeleteDocumentIdentity(ctx context.Context, query *DeleteDocumentIdentityQuery) error
	Delete(ctx context.Context, doc *model.MetaData) error
	GetDocumentForCredential(ctx context.Context, query *GetDocumentForCredential) (*model.Document, error)
	GetDocument(ctx context.Context, query *GetDocumentQuery) (*model.Document, error)
	GetDocumentWithIdentity(ctx context.Context, query *GetDocumentQuery) (*model.CompleteDocument, error)
	GetDocumentsWithIdentity(ctx context.Context, query *GetDocumentQuery) (map[string]*model.CompleteDocument, error)
	DocumentList(ctx context.Context, query *DocumentListQuery) ([]*model.DocumentList, error)
	GetQR(ctx context.Context, attr *model.MetaData) (*openid4vci.QR, error)
	GetQRForUser(ctx context.Context, query *GetQRForUserFilter) (*openid4vci.QR, error)
	GetDocumentCollectID(ctx context.Context, query *GetDocumentCollectIDQuery) (*model.Document, error)
	GetByRevocationID(ctx context.Context, q *model.MetaData) (*model.CompleteDocument, error)
	Replace(ctx context.Context, doc *model.CompleteDocument) error
	SearchDocuments(ctx context.Context, query *SearchDocumentsQuery, limit int64, fields []string, sortFields map[string]int) ([]*model.CompleteDocument, bool, error)
}

// Ensure concrete types implement the interfaces
var _ UsersStore = (*VCUsersColl)(nil)
var _ CredentialOfferStore = (*VCCredentialOfferColl)(nil)
var _ DatastoreStore = (*VCDatastoreColl)(nil)
