package apiv2

import (
	"context"

	"github.com/SUNET/vc/pkg/model"

	"go.opentelemetry.io/otel/codes"
)

// UploadDocumentRequest is the request for uploading a v2 document.
type UploadDocumentRequest struct {
	Meta         *model.V2MetaData `json:"meta" validate:"required"`
	Identities   []string          `json:"identities" validate:"required,min=1"`
	DocumentData map[string]any    `json:"document_data" validate:"required"`
}

// UploadDocumentReply is the response for uploading a v2 document.
type UploadDocumentReply struct {
	DocumentID string `json:"document_id"`
}

// UploadDocument stores a new v2 document.
func (c *Client) UploadDocument(ctx context.Context, req *UploadDocumentRequest) (*UploadDocumentReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:uploadDocument")
	defer span.End()

	doc := &model.V2Document{
		Meta:         req.Meta,
		Identities:   req.Identities,
		DocumentData: req.DocumentData,
	}

	if err := c.datastoreStore.SaveDocument(ctx, doc); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &UploadDocumentReply{DocumentID: doc.Meta.DocumentID}, nil
}

// GetDocumentRequest is the request for retrieving a v2 document.
type GetDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" validate:"required,max=128,printascii"`
}

// GetDocumentReply is the response for retrieving a v2 document.
type GetDocumentReply struct {
	Document *model.V2Document `json:"document"`
}

// GetDocument retrieves a document by its unique key.
func (c *Client) GetDocument(ctx context.Context, req *GetDocumentRequest) (*GetDocumentReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:getDocument")
	defer span.End()

	doc, err := c.datastoreStore.GetDocument(ctx, req.AuthenticSource, req.Scope, req.DocumentID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &GetDocumentReply{Document: doc}, nil
}

// ListDocumentsRequest is the request for listing documents by identifier.
type ListDocumentsRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Identifier      string `json:"identifier" validate:"required,max=128,printascii"`
	Scope           string `json:"scope,omitempty" validate:"omitempty,max=128,printascii"`
}

// ListDocumentsReply is the response for listing documents.
type ListDocumentsReply struct {
	Documents []*model.V2Document `json:"documents"`
}

// ListDocuments lists documents for an identifier.
func (c *Client) ListDocuments(ctx context.Context, req *ListDocumentsRequest) (*ListDocumentsReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:listDocuments")
	defer span.End()

	docs, err := c.datastoreStore.ListDocuments(ctx, req.AuthenticSource, req.Identifier, req.Scope)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &ListDocumentsReply{Documents: docs}, nil
}

// DeleteDocumentRequest is the request for deleting a v2 document.
type DeleteDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" validate:"required,max=128,printascii"`
	DocumentID      string `json:"document_id" validate:"required,max=128,printascii"`
}

// DeleteDocument removes a document.
func (c *Client) DeleteDocument(ctx context.Context, req *DeleteDocumentRequest) error {
	ctx, span := c.tracer.Start(ctx, "apiv2:deleteDocument")
	defer span.End()

	if err := c.datastoreStore.DeleteDocument(ctx, req.AuthenticSource, req.Scope, req.DocumentID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// ResolveDocumentsRequest is the single-step request: resolve identity + fetch documents.
type ResolveDocumentsRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required,max=128,printascii"`
	Scope           string            `json:"scope" validate:"required,max=128,printascii"`
	Attributes      map[string]string `json:"attributes" validate:"required,min=1"`
}

// ResolveDocumentsReply is the response for the resolve+fetch operation.
type ResolveDocumentsReply struct {
	Identifier string              `json:"identifier"`
	Documents  []*model.V2Document `json:"documents"`
}

// ResolveDocuments resolves identity attributes and fetches matching documents in one step.
func (c *Client) ResolveDocuments(ctx context.Context, req *ResolveDocumentsRequest) (*ResolveDocumentsReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:resolveDocuments")
	defer span.End()

	// First resolve identity
	identifier, err := c.datastoreStore.GetIdentityMapping(ctx, req.AuthenticSource, req.Attributes)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Then fetch documents
	docs, err := c.datastoreStore.ListDocuments(ctx, req.AuthenticSource, identifier, req.Scope)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &ResolveDocumentsReply{
		Identifier: identifier,
		Documents:  docs,
	}, nil
}
