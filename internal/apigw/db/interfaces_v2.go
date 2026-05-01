package db

import (
	"context"

	"github.com/SUNET/vc/pkg/model"
)

// DatastoreV2Store defines the interface for v2 datastore operations.
type DatastoreV2Store interface {
	// Identity mapping operations
	CreateIdentityMapping(ctx context.Context, mapping *model.IdentityMapping) (string, error)
	GetIdentityMapping(ctx context.Context, authenticSource string, attributes map[string]string) (string, error)
	UpdateIdentityMapping(ctx context.Context, authenticSource, identifier string, attributes map[string]string) error
	DeleteIdentityMapping(ctx context.Context, authenticSource, identifier string) error

	// Document operations
	SaveDocument(ctx context.Context, doc *model.V2Document) error
	GetDocument(ctx context.Context, authenticSource, scope, documentID string) (*model.V2Document, error)
	ListDocuments(ctx context.Context, authenticSource, identifier, scope string) ([]*model.V2Document, error)
	DeleteDocument(ctx context.Context, authenticSource, scope, documentID string) error

	// Combined resolution: resolve identity attributes then fetch document
	ResolveAndGetDocuments(ctx context.Context, authenticSource, scope string, attributes map[string]string) ([]*model.V2Document, error)
}

// Ensure concrete type implements the interface
var _ DatastoreV2Store = (*VCDatastoreV2Coll)(nil)
