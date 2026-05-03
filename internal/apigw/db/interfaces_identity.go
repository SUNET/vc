package db

import (
	"context"

	"github.com/SUNET/vc/pkg/model"
)

// IdentityStore defines the interface for identity mapping operations
type IdentityStore interface {
	CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error)
	UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error
}

// ResolveMappingQuery is the query for resolving attributes to an authentic_source_person_id
type ResolveMappingQuery struct {
	AuthenticSource string         `json:"authentic_source"`
	Attributes      map[string]any `json:"attributes"`
}

// DeleteMappingQuery is the query for deleting an identity mapping
type DeleteMappingQuery struct {
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// Ensure concrete type implements the interface
var _ IdentityStore = (*VCIdentitiesColl)(nil)
