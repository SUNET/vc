package apiv1

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/google/uuid"
)

// DatastoreUploadReply is the reply for a document upload
type DatastoreUploadReply struct {
	DocumentID string `json:"document_id"`
}

// DatastoreUpload uploads a document with a set of attributes
//
//	@Summary		DatastoreUpload
//	@ID				datastore-upload
//	@Description	Upload a document to the datastore
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DatastoreUploadReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		vcclient.UploadRequest	true	" "
//	@Router			/api/v1/datastore/ [post]
func (c *Client) DatastoreUpload(ctx context.Context, req *vcclient.UploadRequest) (*DatastoreUploadReply, error) {
	if req.Meta.DocumentID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate document_id: %w", err)
		}
		req.Meta.DocumentID = id.String()
	}

	upload := &model.CompleteDocument{
		Meta:               req.Meta,
		DocumentData:       req.DocumentData,
		IdentityMappingIDs: req.IdentityMappingIDs,
	}

	if err := helpers.ValidateDocumentData(ctx, upload, c.log); err != nil {
		c.log.Error(err, "failed to validate document data")
		return nil, err
	}

	// Ensure identity mapping records exist for each referenced identity_mapping_id.
	// This creates records with empty attributes if they don't already exist,
	// allowing the authentic source to later add identity attributes for resolution.
	for _, id := range req.IdentityMappingIDs {
		mapping := &model.IdentityMapping{
			AuthenticSourcePersonID: id,
			AuthenticSource:         req.Meta.AuthenticSource,
		}
		if err := c.identityMappingStore.EnsureMapping(ctx, mapping); err != nil {
			c.log.Error(err, "failed to ensure identity mapping", "identity_mapping_id", id)
			return nil, err
		}
	}

	if err := c.datastoreStore.Save(ctx, upload); err != nil {
		c.log.Error(err, "failed to save document")
		return nil, err
	}

	reply := &DatastoreUploadReply{
		DocumentID: req.Meta.DocumentID,
	}
	return reply, nil
}

// DatastoreBulkUploadRequest is the request for bulk uploading documents
type DatastoreBulkUploadRequest struct {
	Documents map[string]*vcclient.UploadRequest `json:"documents" validate:"required,min=1,dive"`
}

// DatastoreBulkUploadReply is the reply for a bulk document upload
type DatastoreBulkUploadReply struct {
	Count int `json:"count"`
}

// DatastoreBulkUpload uploads multiple documents in a single operation
func (c *Client) DatastoreBulkUpload(ctx context.Context, req *DatastoreBulkUploadRequest) (*DatastoreBulkUploadReply, error) {
	docs := make([]*model.CompleteDocument, 0, len(req.Documents))

	for _, r := range req.Documents {
		if r.Meta.DocumentID == "" {
			id, err := uuid.NewV7()
			if err != nil {
				return nil, fmt.Errorf("failed to generate document_id: %w", err)
			}
			r.Meta.DocumentID = id.String()
		}

		doc := &model.CompleteDocument{
			Meta:               r.Meta,
			DocumentData:       r.DocumentData,
			IdentityMappingIDs: r.IdentityMappingIDs,
		}

		if err := helpers.ValidateDocumentData(ctx, doc, c.log); err != nil {
			return nil, err
		}

		for _, id := range r.IdentityMappingIDs {
			mapping := &model.IdentityMapping{
				AuthenticSourcePersonID: id,
				AuthenticSource:         r.Meta.AuthenticSource,
			}
			if err := c.identityMappingStore.EnsureMapping(ctx, mapping); err != nil {
				return nil, err
			}
		}

		docs = append(docs, doc)
	}

	if err := c.datastoreStore.SaveMany(ctx, docs); err != nil {
		c.log.Error(err, "failed to bulk save documents")
		return nil, err
	}

	return &DatastoreBulkUploadReply{Count: len(docs)}, nil
}

// DatastoreAddIdentityRequest is the request for adding identity to a document
type DatastoreAddIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" validate:"required"`

	// required: true
	// example: pid
	Scope string `json:"scope" validate:"required"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" validate:"required"`

	IdentityMappingIDs []string `json:"identity_mapping_ids" validate:"required,min=1,dive,required,max=128,printascii"`
}

// DatastoreAddIdentity adds an identity to a document
//
//	@Summary		DatastoreAddIdentity
//	@ID				add-identity
//	@Description	Adding array of identity mapping IDs to one document
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		DatastoreAddIdentityRequest	true	" "
//	@Router			/api/v1/datastore/identity [put]
func (c *Client) DatastoreAddIdentity(ctx context.Context, req *DatastoreAddIdentityRequest) error {
	err := c.datastoreStore.AddIdentity(ctx, &db.AddIdentityQuery{
		AuthenticSource:    req.AuthenticSource,
		Scope:              req.Scope,
		DocumentID:         req.DocumentID,
		IdentityMappingIDs: req.IdentityMappingIDs,
	})
	if err != nil {
		return err
	}

	return nil
}

// DatastoreDeleteIdentityRequest is the request for DatastoreDeleteIdentity
type DatastoreDeleteIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" validate:"required"`

	// required: true
	// example: pid
	Scope string `json:"scope" validate:"required"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" validate:"required"`

	// required: true
	// example: 83c1a3c8-3e1a-11ef-9c01-6b6642c8d638
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required"`
}

// DatastoreDeleteIdentity deletes an identity from a document
//
//	@Summary		DatastoreDeleteIdentity
//	@ID				delete-identity
//	@Description	Delete identity to document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		DatastoreDeleteIdentityRequest	true	" "
//	@Router			/api/v1/datastore/identity [delete]
func (c *Client) DatastoreDeleteIdentity(ctx context.Context, req *DatastoreDeleteIdentityRequest) error {
	err := c.datastoreStore.DeleteIdentity(ctx, &db.DeleteIdentityQuery{
		AuthenticSource:         req.AuthenticSource,
		Scope:                   req.Scope,
		DocumentID:              req.DocumentID,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
	if err != nil {
		return err
	}

	return nil
}

// DatastoreDeleteRequest is the request for DatastoreDelete
type DatastoreDeleteRequest struct {
	// required: true
	// example: skatteverket
	AuthenticSource string `json:"authentic_source" validate:"required"`

	// required: true
	// example: 5e7a981c-c03f-11ee-b116-9b12c59362b9
	DocumentID string `json:"document_id" validate:"required"`

	// required: true
	// example: pid
	Scope string `json:"scope" validate:"required"`
}

// DatastoreDelete deletes a specific document
//
//	@Summary		DatastoreDelete
//	@ID				delete-document
//	@Description	delete one document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		204	"No Content"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DatastoreDeleteRequest	true	" "
//	@Router			/api/v1/datastore [delete]
func (c *Client) DatastoreDelete(ctx context.Context, req *DatastoreDeleteRequest) error {
	err := c.datastoreStore.Delete(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		Scope:           req.Scope,
		DocumentID:      req.DocumentID,
	})
	if err != nil {
		return err
	}

	return nil
}

// DatastoreGetRequest is the request for DatastoreGet
type DatastoreGetRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	Scope           string `json:"scope" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// DatastoreGetReply is the reply for a generic document
type DatastoreGetReply struct {
	Data *model.Document `json:"data"`
}

// DatastoreGet return a specific document
//
//	@Summary		DatastoreGet
//	@ID				get-document
//	@Description	Get document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DatastoreGetReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DatastoreGetRequest		true	" "
//	@Router			/api/v1/datastore [post]
func (c *Client) DatastoreGet(ctx context.Context, req *DatastoreGetRequest) (*DatastoreGetReply, error) {
	doc, err := c.datastoreStore.Get(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		Scope:           req.Scope,
		DocumentID:      req.DocumentID,
	})
	if err != nil {
		return nil, err
	}
	reply := &DatastoreGetReply{
		Data: doc,
	}

	return reply, nil
}

// DatastoreListRequest is the request for DatastoreList
type DatastoreListRequest struct {
	AuthenticSource   string `json:"authentic_source"`
	IdentityMappingID string `json:"identity_mapping_id" validate:"required"`
	Scope             string `json:"scope"`
	ValidFrom         int64  `json:"valid_from"`
	ValidTo           int64  `json:"valid_to"`
}

// DatastoreListReply is the reply for a list of documents
type DatastoreListReply struct {
	Data []*model.DocumentList `json:"data"`
}

// DatastoreList return a list of metadata for a specific identity
//
//	@Summary		DatastoreList
//	@ID				document-list
//	@Description	List documents for an identity
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DatastoreListReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DatastoreListRequest	true	" "
//	@Router			/api/v1/datastore/list [post]
func (c *Client) DatastoreList(ctx context.Context, req *DatastoreListRequest) (*DatastoreListReply, error) {
	docs, err := c.datastoreStore.List(ctx, &db.ListQuery{
		AuthenticSource:   req.AuthenticSource,
		IdentityMappingID: req.IdentityMappingID,
		Scope:             req.Scope,
		ValidFrom:         req.ValidFrom,
		ValidTo:           req.ValidTo,
	})
	if err != nil {
		return nil, err
	}

	reply := &DatastoreListReply{
		Data: docs,
	}

	return reply, nil
}

// DatastoreGetByKeyRequest is the request for getting a document by its key
type DatastoreGetByKeyRequest struct {
	AuthenticSource string `json:"authentic_source" form:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" form:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" form:"document_id" validate:"required,max=128,printascii"`
}

// DatastoreGetByKeyReply is the reply for a document retrieval
type DatastoreGetByKeyReply struct {
	Data *model.CompleteDocument `json:"data"`
}

// DatastoreGetByKey retrieves a document by its natural key
//
//	@Summary		DatastoreGetByKey
//	@ID				get-document-by-key
//	@Description	Get a document by authentic_source, scope, and document_id
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200					{object}	DatastoreGetByKeyReply	"Success"
//	@Failure		400					{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			authentic_source	query		string					true	"Authentic source"
//	@Param			scope				query		string					true	"Scope"
//	@Param			document_id			query		string					true	"Document ID"
//	@Router			/api/v1/datastore/ [get]
func (c *Client) DatastoreGetByKey(ctx context.Context, req *DatastoreGetByKeyRequest) (*DatastoreGetByKeyReply, error) {
	doc, err := c.datastoreStore.GetByKey(ctx, req.AuthenticSource, req.Scope, req.DocumentID)
	if err != nil {
		return nil, err
	}

	reply := &DatastoreGetByKeyReply{
		Data: doc,
	}
	return reply, nil
}

// DatastoreResolveRequest is the request for resolving identity attributes to documents
type DatastoreResolveRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string            `json:"scope" validate:"required,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,dive,keys,safe_key,endkeys"`
}

// DatastoreResolveReply is the reply for resolved documents
type DatastoreResolveReply struct {
	AuthenticSourcePersonID string                `json:"authentic_source_person_id"`
	Data                    []*model.DocumentList `json:"data"`
}

// DatastoreResolve resolves identity attributes (e.g. from an OIDC/SAML session) to an
// internal identifier via the identity mapping store, then returns all documents
// associated with that identifier, filtered by authentic source and scope.
//
//	@Summary		DatastoreResolve
//	@ID				resolve-document
//	@Description	Resolve identity attributes to documents
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DatastoreResolveReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DatastoreResolveRequest	true	" "
//	@Router			/api/v1/datastore/resolve [post]
func (c *Client) DatastoreResolve(ctx context.Context, req *DatastoreResolveRequest) (*DatastoreResolveReply, error) {
	personID, err := c.identityMappingStore.ResolveMapping(ctx, &db.ResolveMappingQuery{
		AuthenticSource: req.AuthenticSource,
		Attributes:      req.Attributes,
	})
	if err != nil {
		return nil, err
	}

	docs, err := c.datastoreStore.List(ctx, &db.ListQuery{
		AuthenticSource:   req.AuthenticSource,
		Scope:             req.Scope,
		IdentityMappingID: personID,
	})
	if err != nil {
		return nil, err
	}

	reply := &DatastoreResolveReply{
		AuthenticSourcePersonID: personID,
		Data:                    docs,
	}
	return reply, nil
}

// DatastoreDeleteByKeyRequest is the request for deleting a document
type DatastoreDeleteByKeyRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" validate:"required,max=128,printascii"`
}

// DatastoreDeleteByKey deletes a document by its natural key
//
//	@Summary		DatastoreDeleteByKey
//	@ID				delete-document-by-key
//	@Description	Delete a document by authentic_source, scope, and document_id
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		204	"No Content"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		DatastoreDeleteByKeyRequest	true	" "
//	@Router			/api/v1/datastore/ [delete]
func (c *Client) DatastoreDeleteByKey(ctx context.Context, req *DatastoreDeleteByKeyRequest) error {
	return c.datastoreStore.DeleteByKey(ctx, req.AuthenticSource, req.Scope, req.DocumentID)
}

// DatastoreReplace replaces an existing document in the datastore
//
//	@Summary		DatastoreReplace
//	@ID				datastore-replace
//	@Description	Replace an existing document in the datastore
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		vcclient.UploadRequest	true	" "
//	@Router			/api/v1/datastore/ [put]
func (c *Client) DatastoreReplace(ctx context.Context, req *vcclient.UploadRequest) error {
	upload := &model.CompleteDocument{
		Meta:               req.Meta,
		DocumentData:       req.DocumentData,
		IdentityMappingIDs: req.IdentityMappingIDs,
	}

	if err := helpers.ValidateDocumentData(ctx, upload, c.log); err != nil {
		c.log.Error(err, "failed to validate document data")
		return err
	}

	if err := c.datastoreStore.Replace(ctx, upload); err != nil {
		c.log.Error(err, "failed to replace document")
		return err
	}

	return nil
}

// DatastoreSearchRequest is the request for searching documents
type DatastoreSearchRequest struct {
	Search                  string   `json:"search" form:"search"`
	AuthenticSource         string   `json:"authentic_source" form:"authentic_source"`
	Scope                   string   `json:"scope" form:"scope"`
	Limit                   int64    `json:"limit" form:"limit"`
	AllowedAuthenticSources []string `json:"-" form:"-"`
}

// DatastoreSearchReply is the reply for searching documents
type DatastoreSearchReply struct {
	Data []*model.CompleteDocument `json:"data"`
}

// DatastoreSearch searches documents
//
//	@Summary		DatastoreSearch
//	@ID				search-documents
//	@Description	Search documents in the datastore
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DatastoreSearchReply	"Success"
//	@Param			search			query	string	false	"Search term"
//	@Param			authentic_source	query	string	false	"Filter by authentic source"
//	@Param			scope			query	string	false	"Filter by scope"
//	@Param			limit			query	int		false	"Max results (default 50, max 200)"
//	@Router			/api/v1/datastore/search [get]
func (c *Client) DatastoreSearch(ctx context.Context, req *DatastoreSearchRequest) (*DatastoreSearchReply, error) {
	if len(req.AllowedAuthenticSources) == 0 {
		return &DatastoreSearchReply{Data: []*model.CompleteDocument{}}, nil
	}

	limit := req.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	docs, err := c.datastoreStore.Search(ctx, &db.SearchDocumentsQuery{
		Search:                  req.Search,
		AuthenticSource:         req.AuthenticSource,
		Scope:                   req.Scope,
		Limit:                   limit,
		AllowedAuthenticSources: req.AllowedAuthenticSources,
	})
	if err != nil {
		return nil, err
	}
	if docs == nil {
		docs = []*model.CompleteDocument{}
	}
	reply := &DatastoreSearchReply{
		Data: docs,
	}

	return reply, nil
}
