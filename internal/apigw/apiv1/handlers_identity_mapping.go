package apiv1

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"

	"github.com/google/uuid"
)

// IdentityMappingCreateRequest is the request for creating an identity mapping
type IdentityMappingCreateRequest struct {
	AuthenticSource         string         `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string         `json:"authentic_source_person_id" validate:"omitempty,max=128,printascii"`
	Attributes              map[string]any `json:"attributes,omitempty"`
}

// IdentityMappingCreateReply is the reply containing the identifier
type IdentityMappingCreateReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// IdentityMappingCreate creates a new identity mapping and returns the identifier
//
//	@Summary		IdentityMappingCreate
//	@ID				create-identity-mapping
//	@Description	Create a new identity mapping
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IdentityMappingCreateReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		IdentityMappingCreateRequest	true	" "
//	@Router			/api/v1/identity/mapping [post]
func (c *Client) IdentityMappingCreate(ctx context.Context, req *IdentityMappingCreateRequest) (*IdentityMappingCreateReply, error) {
	identifier := req.AuthenticSourcePersonID
	if identifier == "" {
		identifier = uuid.New().String()
	}

	mapping := &model.IdentityMapping{
		AuthenticSourcePersonID: identifier,
		AuthenticSource:         req.AuthenticSource,
		Attributes:              req.Attributes,
	}

	if err := c.identityMappingStore.CreateMapping(ctx, mapping); err != nil {
		return nil, err
	}

	reply := &IdentityMappingCreateReply{
		AuthenticSourcePersonID: identifier,
	}

	return reply, nil
}

// IdentityMappingResolveRequest is the request for resolving attributes to an identifier
type IdentityMappingResolveRequest struct {
	AuthenticSource string         `json:"authentic_source" validate:"required,max=128,printascii"`
	Attributes      map[string]any `json:"attributes" validate:"required"`
}

// IdentityMappingResolveReply is the reply with the resolved identifier
type IdentityMappingResolveReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// IdentityMappingResolve resolves attributes to an authentic_source_person_id
//
//	@Summary		IdentityMappingResolve
//	@ID				resolve-identity-mapping
//	@Description	Resolve attributes to an authentic_source_person_id
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IdentityMappingResolveReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		IdentityMappingResolveRequest	true	" "
//	@Router			/api/v1/identity/mapping/resolve [post]
func (c *Client) IdentityMappingResolve(ctx context.Context, req *IdentityMappingResolveRequest) (*IdentityMappingResolveReply, error) {
	personID, err := c.identityMappingStore.ResolveMapping(ctx, &db.ResolveMappingQuery{
		AuthenticSource: req.AuthenticSource,
		Attributes:      req.Attributes,
	})
	if err != nil {
		return nil, err
	}

	return &IdentityMappingResolveReply{
		AuthenticSourcePersonID: personID,
	}, nil
}

// IdentityMappingUpdateRequest is the request for updating an identity mapping
type IdentityMappingUpdateRequest struct {
	AuthenticSource         string         `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string         `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
	Attributes              map[string]any `json:"attributes,omitempty"`
}

// IdentityMappingUpdate updates an existing identity mapping
//
//	@Summary		IdentityMappingUpdate
//	@ID				update-identity-mapping
//	@Description	Update an existing identity mapping
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		IdentityMappingUpdateRequest	true	" "
//	@Router			/api/v1/identity/mapping [put]
func (c *Client) IdentityMappingUpdate(ctx context.Context, req *IdentityMappingUpdateRequest) error {
	mapping := &model.IdentityMapping{
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		AuthenticSource:         req.AuthenticSource,
		Attributes:              req.Attributes,
	}

	return c.identityMappingStore.UpdateMapping(ctx, mapping)
}

// IdentityMappingDeleteRequest is the request for deleting an identity mapping
type IdentityMappingDeleteRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
}

// IdentityMappingDelete deletes an identity mapping
//
//	@Summary		IdentityMappingDelete
//	@ID				delete-identity-mapping
//	@Description	Delete an identity mapping
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		IdentityMappingDeleteRequest	true	" "
//	@Router			/api/v1/identity/mapping [delete]
func (c *Client) IdentityMappingDelete(ctx context.Context, req *IdentityMappingDeleteRequest) error {
	return c.identityMappingStore.DeleteMapping(ctx, &db.DeleteMappingQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
}
