package apiv1

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"

	"github.com/google/uuid"
)

// CreateIdentityMappingRequest is the request for creating an identity mapping
type CreateIdentityMappingRequest struct {
	AuthenticSource         string         `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string         `json:"authentic_source_person_id" validate:"omitempty,max=128,printascii"`
	Attributes              map[string]any `json:"attributes,omitempty"`
}

// CreateIdentityMappingReply is the reply containing the identifier
type CreateIdentityMappingReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// CreateIdentityMapping creates a new identity mapping and returns the identifier
func (c *Client) CreateIdentityMapping(ctx context.Context, req *CreateIdentityMappingRequest) (*CreateIdentityMappingReply, error) {
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

	reply := &CreateIdentityMappingReply{
		AuthenticSourcePersonID: identifier,
	}

	return reply, nil
}

// ResolveIdentityMappingRequest is the request for resolving attributes to an identifier
type ResolveIdentityMappingRequest struct {
	AuthenticSource string         `json:"authentic_source" validate:"required,max=128,printascii"`
	Attributes      map[string]any `json:"attributes" validate:"required"`
}

// ResolveIdentityMappingReply is the reply with the resolved identifier
type ResolveIdentityMappingReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// ResolveIdentityMapping resolves attributes to an authentic_source_person_id
func (c *Client) ResolveIdentityMapping(ctx context.Context, req *ResolveIdentityMappingRequest) (*ResolveIdentityMappingReply, error) {
	personID, err := c.identityMappingStore.ResolveMapping(ctx, &db.ResolveMappingQuery{
		AuthenticSource: req.AuthenticSource,
		Attributes:      req.Attributes,
	})
	if err != nil {
		return nil, err
	}

	return &ResolveIdentityMappingReply{
		AuthenticSourcePersonID: personID,
	}, nil
}

// UpdateIdentityMappingRequest is the request for updating an identity mapping
type UpdateIdentityMappingRequest struct {
	AuthenticSource         string         `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string         `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
	Attributes              map[string]any `json:"attributes,omitempty"`
}

// UpdateIdentityMapping updates an existing identity mapping
func (c *Client) UpdateIdentityMapping(ctx context.Context, req *UpdateIdentityMappingRequest) error {
	mapping := &model.IdentityMapping{
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		AuthenticSource:         req.AuthenticSource,
		Attributes:              req.Attributes,
	}

	return c.identityMappingStore.UpdateMapping(ctx, mapping)
}

// DeleteIdentityMappingRequest is the request for deleting an identity mapping
type DeleteIdentityMappingRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
}

// DeleteIdentityMapping deletes an identity mapping
func (c *Client) DeleteIdentityMapping(ctx context.Context, req *DeleteIdentityMappingRequest) error {
	return c.identityMappingStore.DeleteMapping(ctx, &db.DeleteMappingQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
}

// UploadDocumentRequest is the request for uploading a document (new simplified API)
type UploadDocumentRequest struct {
	Meta               *model.MetaData `json:"meta" validate:"required"`
	IdentityMappingIDs []string        `json:"identity_mapping_ids"`
	DocumentData       map[string]any  `json:"document_data" validate:"required"`
}

// UploadDocumentReply is the reply after uploading a document
type UploadDocumentReply struct {
	DocumentID string `json:"document_id"`
}

// UploadDocument uploads a document, auto-generating document_id if empty
func (c *Client) UploadDocument(ctx context.Context, req *UploadDocumentRequest) (*UploadDocumentReply, error) {
	if req.Meta.DocumentID == "" {
		req.Meta.DocumentID = uuid.New().String()
	}

	if req.IdentityMappingIDs == nil {
		req.IdentityMappingIDs = []string{}
	}

	doc := &model.CompleteDocument{
		Meta:               req.Meta,
		IdentityMappingIDs: req.IdentityMappingIDs,
		DocumentData:       req.DocumentData,
	}

	if err := c.datastoreStore.Save(ctx, doc); err != nil {
		return nil, err
	}

	return &UploadDocumentReply{
		DocumentID: req.Meta.DocumentID,
	}, nil
}

// GetDocumentByKeyRequest is the request for getting a document by its key
type GetDocumentByKeyRequest struct {
	AuthenticSource string `json:"authentic_source" form:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" form:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" form:"document_id" validate:"required,max=128,printascii"`
}

// GetDocumentByKeyReply is the reply for a document retrieval
type GetDocumentByKeyReply struct {
	Data *model.CompleteDocument `json:"data"`
}

// GetDocumentByKey retrieves a document by its natural key
func (c *Client) GetDocumentByKey(ctx context.Context, req *GetDocumentByKeyRequest) (*GetDocumentByKeyReply, error) {
	doc, err := c.datastoreStore.GetDocumentByKey(ctx, req.AuthenticSource, req.Scope, req.DocumentID)
	if err != nil {
		return nil, err
	}

	return &GetDocumentByKeyReply{
		Data: doc,
	}, nil
}

// ListDocumentsRequest is the request for listing documents by identifier
type ListDocumentsRequest struct {
	Identifier string `json:"identifier" validate:"required,max=128,printascii"`
}

// ListDocumentsReply is the reply for listing documents
type ListDocumentsReply struct {
	Data []*model.CompleteDocument `json:"data"`
}

// ListDocumentsByIdentifier lists documents for a given identifier
func (c *Client) ListDocumentsByIdentifier(ctx context.Context, req *ListDocumentsRequest) (*ListDocumentsReply, error) {
	docs, err := c.datastoreStore.ListDocumentsByIdentifier(ctx, req.Identifier)
	if err != nil {
		return nil, err
	}

	return &ListDocumentsReply{
		Data: docs,
	}, nil
}

// ResolveDocumentRequest is the request for resolving identity + getting document
type ResolveDocumentRequest struct {
	AuthenticSource string         `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string         `json:"scope" validate:"required,max=128,printascii"`
	Attributes      map[string]any `json:"attributes" validate:"required"`
}

// ResolveDocumentReply is the reply for a resolved document
type ResolveDocumentReply struct {
	Data []*model.CompleteDocument `json:"data"`
}

// ResolveDocument resolves identity attributes and returns matching documents
func (c *Client) ResolveDocument(ctx context.Context, req *ResolveDocumentRequest) (*ResolveDocumentReply, error) {
	// Step 1: Resolve attributes to an identifier
	personID, err := c.identityMappingStore.ResolveMapping(ctx, &db.ResolveMappingQuery{
		AuthenticSource: req.AuthenticSource,
		Attributes:      req.Attributes,
	})
	if err != nil {
		return nil, err
	}

	// Step 2: Find documents referencing this identifier
	docs, err := c.datastoreStore.ListDocumentsByIdentifier(ctx, personID)
	if err != nil {
		return nil, err
	}

	// Filter by scope if specified
	if req.Scope != "" {
		filtered := make([]*model.CompleteDocument, 0)
		for _, doc := range docs {
			if doc.Meta != nil && doc.Meta.Scope == req.Scope {
				filtered = append(filtered, doc)
			}
		}
		docs = filtered
	}

	return &ResolveDocumentReply{
		Data: docs,
	}, nil
}

// DeleteDocumentByKeyRequest is the request for deleting a document
type DeleteDocumentByKeyRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" validate:"required,max=128,printascii"`
}

// DeleteDocumentByKey deletes a document by its natural key
func (c *Client) DeleteDocumentByKey(ctx context.Context, req *DeleteDocumentByKeyRequest) error {
	return c.datastoreStore.DeleteDocumentByKey(ctx, req.AuthenticSource, req.Scope, req.DocumentID)
}
