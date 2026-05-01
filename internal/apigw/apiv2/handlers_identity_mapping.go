package apiv2

import (
	"context"

	"github.com/SUNET/vc/pkg/model"

	"go.opentelemetry.io/otel/codes"
)

// CreateIdentityMappingRequest is the request for creating an identity mapping.
type CreateIdentityMappingRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Identifier      string            `json:"identifier,omitempty" validate:"omitempty,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,min=1"`
}

// CreateIdentityMappingReply is the response for creating an identity mapping.
type CreateIdentityMappingReply struct {
	Identifier string `json:"identifier"`
}

// CreateIdentityMapping creates a new identity mapping.
func (c *Client) CreateIdentityMapping(ctx context.Context, req *CreateIdentityMappingRequest) (*CreateIdentityMappingReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:createIdentityMapping")
	defer span.End()

	mapping := &model.IdentityMapping{
		AuthenticSource: req.AuthenticSource,
		Identifier:      req.Identifier,
		Attributes:      req.Attributes,
	}

	identifier, err := c.datastoreStore.CreateIdentityMapping(ctx, mapping)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &CreateIdentityMappingReply{Identifier: identifier}, nil
}

// ResolveIdentityMappingRequest is the request for resolving identity attributes to an identifier.
type ResolveIdentityMappingRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,min=1"`
}

// ResolveIdentityMappingReply is the response for resolving an identity mapping.
type ResolveIdentityMappingReply struct {
	Identifier string `json:"identifier"`
}

// ResolveIdentityMapping resolves attributes to an identifier.
func (c *Client) ResolveIdentityMapping(ctx context.Context, req *ResolveIdentityMappingRequest) (*ResolveIdentityMappingReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:resolveIdentityMapping")
	defer span.End()

	identifier, err := c.datastoreStore.GetIdentityMapping(ctx, req.AuthenticSource, req.Attributes)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &ResolveIdentityMappingReply{Identifier: identifier}, nil
}

// UpdateIdentityMappingRequest is the request for updating an identity mapping.
type UpdateIdentityMappingRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Identifier      string            `json:"identifier" validate:"required,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,min=1"`
}

// UpdateIdentityMapping updates the attributes for an existing mapping.
func (c *Client) UpdateIdentityMapping(ctx context.Context, req *UpdateIdentityMappingRequest) error {
	ctx, span := c.tracer.Start(ctx, "apiv2:updateIdentityMapping")
	defer span.End()

	if err := c.datastoreStore.UpdateIdentityMapping(ctx, req.AuthenticSource, req.Identifier, req.Attributes); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// DeleteIdentityMappingRequest is the request for deleting an identity mapping.
type DeleteIdentityMappingRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Identifier      string `json:"identifier" validate:"required,max=128,printascii"`
}

// DeleteIdentityMapping removes an identity mapping.
func (c *Client) DeleteIdentityMapping(ctx context.Context, req *DeleteIdentityMappingRequest) error {
	ctx, span := c.tracer.Start(ctx, "apiv2:deleteIdentityMapping")
	defer span.End()

	if err := c.datastoreStore.DeleteIdentityMapping(ctx, req.AuthenticSource, req.Identifier); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
