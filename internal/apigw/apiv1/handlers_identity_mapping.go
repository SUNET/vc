package apiv1

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"

	"github.com/google/uuid"
)

// IdentityMappingCreateRequest is the request for creating an identity mapping
type IdentityMappingCreateRequest struct {
	AuthenticSource         string            `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string            `json:"authentic_source_person_id" validate:"omitempty,max=128,printascii"`
	Attributes              map[string]string `json:"attributes,omitempty" validate:"omitempty,dive,keys,safe_key,endkeys"`
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
//	@Success		200	{object}	IdentityMappingCreateReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		IdentityMappingCreateRequest	true	" "
//	@Router			/api/v1/identity/mapping [post]
func (c *Client) IdentityMappingCreate(ctx context.Context, req *IdentityMappingCreateRequest) (*IdentityMappingCreateReply, error) {
	identifier := req.AuthenticSourcePersonID
	if identifier == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUIDv7: %w", err)
		}
		identifier = id.String()
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
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,dive,keys,safe_key,endkeys"`
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

	reply := &IdentityMappingResolveReply{
		AuthenticSourcePersonID: personID,
	}
	
	return reply, nil
}

// IdentityMappingUpdateRequest is the request for updating an identity mapping
type IdentityMappingUpdateRequest struct {
	AuthenticSource         string            `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string            `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
	Attributes              map[string]string `json:"attributes,omitempty" validate:"omitempty,dive,keys,safe_key,endkeys"`
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

// IdentityMappingSearchRequest is the request for searching identity mappings
type IdentityMappingSearchRequest struct {
	Search                  string   `json:"search" form:"search"`
	AuthenticSource         string   `json:"authentic_source" form:"authentic_source"`
	Limit                   int64    `json:"limit" form:"limit"`
	AllowedAuthenticSources []string `json:"-" form:"-"`
}

// IdentityMappingSearchReply is the reply for searching identity mappings
type IdentityMappingSearchReply struct {
	Data []*model.IdentityMapping `json:"data"`
}

// IdentityMappingSearch searches identity mappings
//
//	@Summary		IdentityMappingSearch
//	@ID				search-identity-mappings
//	@Description	Search identity mappings
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IdentityMappingSearchReply	"Success"
//	@Param			search			query	string	false	"Search term"
//	@Param			authentic_source	query	string	false	"Filter by authentic source"
//	@Param			limit			query	int		false	"Max results (default 50, max 200)"
//	@Router			/api/v1/identity/mapping/search [get]
func (c *Client) IdentityMappingSearch(ctx context.Context, req *IdentityMappingSearchRequest) (*IdentityMappingSearchReply, error) {
	limit := req.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	mappings, err := c.identityMappingStore.SearchMappings(ctx, &db.SearchMappingsQuery{
		Search:                  req.Search,
		AuthenticSource:         req.AuthenticSource,
		Limit:                   limit,
		AllowedAuthenticSources: req.AllowedAuthenticSources,
	})
	if err != nil {
		return nil, err
	}
	if mappings == nil {
		mappings = []*model.IdentityMapping{}
	}

	reply := &IdentityMappingSearchReply{Data: mappings}

	return reply, nil
}
