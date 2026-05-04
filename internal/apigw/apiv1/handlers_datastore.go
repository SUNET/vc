package apiv1

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/vcclient"
)

// Upload uploads a document with a set of attributes
//
//	@Summary		Upload
//	@ID				generic-upload
//	@Description	Upload endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		vcclient.UploadRequest	true	" "
//	@Router			/upload [post]
func (c *Client) Upload(ctx context.Context, req *vcclient.UploadRequest) error {
	credentialOfferParameter := openid4vci.CredentialOfferParameters{
		CredentialIssuer: c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{
			req.Meta.Scope,
		},
		Grants: map[string]any{
			"authorization_code": openid4vci.GrantAuthorizationCode{
				IssuerState: fmt.Sprintf("document_id=%s&authentic_source=%s", req.Meta.DocumentID, req.Meta.AuthenticSource),
			},
		},
	}

	var qr *openid4vci.QR
	switch c.cfg.Common.CredentialOfferQR.Type {
	case "credential_offer":
		credentialOffer, err := credentialOfferParameter.CredentialOffer()
		if err != nil {
			return err
		}

		// Empty string defaults to "openid-credential-offer://" protocol handler
		qr, err = credentialOffer.QR(c.cfg.Common.CredentialOfferQR.QR.RecoveryLevel, c.cfg.Common.CredentialOfferQR.QR.Size, "")
		if err != nil {
			return err
		}

	case "credential_offer_uri":
		credentialOffer, err := credentialOfferParameter.CredentialOfferURI()
		if err != nil {
			return err
		}

		// Empty string defaults to "openid-credential-offer://" protocol handler
		qr, err = credentialOffer.QR(c.cfg.Common.CredentialOfferQR.QR.RecoveryLevel, c.cfg.Common.CredentialOfferQR.QR.Size, "", c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL)
		if err != nil {
			return err
		}

		uuid, err := credentialOffer.UUID()
		if err != nil {
			return err
		}

		doc := &db.CredentialOfferDocument{
			UUID:                      uuid,
			CredentialOfferParameters: credentialOfferParameter,
		}

		if err := c.credentialOfferStore.Save(ctx, doc); err != nil {
			return err
		}
	}

	upload := &model.CompleteDocument{
		Meta:               req.Meta,
		DocumentData:       req.DocumentData,
		IdentityMappingIDs: req.IdentityMappingIDs,
		QR:                 qr,
	}

	if err := helpers.ValidateDocumentData(ctx, upload, c.log); err != nil {
		c.log.Error(err, "failed to validate document data")
		return err
	}

	if err := c.datastoreStore.Save(ctx, upload); err != nil {
		c.log.Error(err, "failed to save document")
		return err
	}

	return nil
}

// Notification return QR code and DeepLink for a document
//
//	@Summary		Notification
//	@ID				generic-notification
//	@Description	notification endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	vcclient.NotificationReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		vcclient.NotificationRequest	true	" "
//	@Router			/notification [post]
func (c *Client) Notification(ctx context.Context, req *vcclient.NotificationRequest) (*vcclient.NotificationReply, error) {
	qrCode, err := c.datastoreStore.GetQR(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		Scope:           req.Scope,
		DocumentID:      req.DocumentID,
	})
	if err != nil {
		return nil, err
	}

	reply := &vcclient.NotificationReply{
		Data: qrCode,
	}
	return reply, nil
}


// AddDocumentIdentityRequest is the request for DocumentIdentity
type AddDocumentIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" validate:"required"`

	// required: true
	// example: pid
	Scope string `json:"scope" validate:"required"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" validate:"required"`

	IdentityMappingIDs []*model.Identity `json:"identity_mapping_ids" validate:"required"`
}

// AddDocumentIdentity adds an identity to a document
//
//	@Summary		AddDocumentIdentity
//	@ID				add-document-identity
//	@Description	Adding array of identity mapping IDs to one document
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		AddDocumentIdentityRequest	true	" "
//	@Router			/document/identity [put]
func (c *Client) AddDocumentIdentity(ctx context.Context, req *AddDocumentIdentityRequest) error {
	err := c.datastoreStore.AddDocumentIdentity(ctx, &db.AddDocumentIdentityQuery{
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

// DeleteDocumentIdentityRequest is the request for DeleteDocumentIdentity
type DeleteDocumentIdentityRequest struct {
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

// DeleteDocumentIdentity deletes an identity from a document
//
//	@Summary		DeleteDocumentIdentity
//	@ID				delete-document-identity
//	@Description	Delete identity to document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		DeleteDocumentIdentityRequest	true	" "
//	@Router			/document/identity [delete]
func (c *Client) DeleteDocumentIdentity(ctx context.Context, req *DeleteDocumentIdentityRequest) error {
	err := c.datastoreStore.DeleteDocumentIdentity(ctx, &db.DeleteDocumentIdentityQuery{
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

// DeleteDocumentRequest is the request for DeleteDocument
type DeleteDocumentRequest struct {
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

// DeleteDocument deletes a specific document
//
//	@Summary		DeleteDocument
//	@ID				delete-document
//	@Description	delete one document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DeleteDocumentRequest	true	" "
//	@Router			/document [delete]
func (c *Client) DeleteDocument(ctx context.Context, req *DeleteDocumentRequest) error {
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

// GetDocumentRequest is the request for GetDocument
type GetDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	Scope           string `json:"scope" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// GetDocumentReply is the reply for a generic document
type GetDocumentReply struct {
	Data *model.Document `json:"data"`
}

// GetDocument return a specific document
//
//	@Summary		GetDocument
//	@ID				get-document
//	@Description	Get document endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetDocumentReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		GetDocumentRequest		true	" "
//	@Router			/document [post]
func (c *Client) GetDocument(ctx context.Context, req *GetDocumentRequest) (*GetDocumentReply, error) {
	query := &db.GetDocumentQuery{
		Meta: &model.MetaData{
			AuthenticSource: req.AuthenticSource,
			Scope:           req.Scope,
			DocumentID:      req.DocumentID,
		},
	}
	doc, err := c.datastoreStore.GetDocument(ctx, query)
	if err != nil {
		return nil, err
	}
	reply := &GetDocumentReply{
		Data: doc,
	}

	return reply, nil
}

// DocumentListRequest is the request for DocumentList
type DocumentListRequest struct {
	AuthenticSource string          `json:"authentic_source"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	Scope           string          `json:"scope"`
	ValidFrom       int64           `json:"valid_from"`
	ValidTo         int64           `json:"valid_to"`
}

// DocumentListReply is the reply for a list of documents
type DocumentListReply struct {
	Data []*model.DocumentList `json:"data"`
}

// DocumentList return a list of metadata for a specific identity
//
//	@Summary		DocumentList
//	@ID				document-list
//	@Description	List documents for an identity
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	DocumentListReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DocumentListRequest		true	" "
//	@Router			/document/list [post]
func (c *Client) DocumentList(ctx context.Context, req *DocumentListRequest) (*DocumentListReply, error) {
	docs, err := c.datastoreStore.DocumentList(ctx, &db.DocumentListQuery{
		AuthenticSource: req.AuthenticSource,
		Identity:        req.Identity,
		Scope:           req.Scope,
		ValidFrom:       req.ValidFrom,
		ValidTo:         req.ValidTo,
	})
	if err != nil {
		return nil, err
	}
	resp := &DocumentListReply{
		Data: docs,
	}
	return resp, nil
}

// SearchDocuments search for documents
func (c *Client) SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error) {
	docs, hasMore, err := c.datastoreStore.SearchDocuments(ctx, &db.SearchDocumentsQuery{
		AuthenticSource: req.AuthenticSource,
		Scope:           req.Scope,
		DocumentID:      req.DocumentID,
		CollectID:       req.CollectID,

		AuthenticSourcePersonID: req.AuthenticSourcePersonID,

		FamilyName: req.FamilyName,
		GivenName:  req.GivenName,
		BirthDate:  req.BirthDate,
		BirthPlace: req.BirthPlace,
	}, req.Limit, req.Fields, req.SortFields)

	if err != nil {
		return nil, err
	}
	resp := &model.SearchDocumentsReply{
		Documents:      docs,
		HasMoreResults: hasMore,
	}
	return resp, nil
}
