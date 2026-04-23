package apiv1

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/vcclient"

	"go.opentelemetry.io/otel/codes"
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
	if req.Meta.Collect == nil || req.Meta.Collect.ID == "" {
		collect := &model.Collect{
			ID: req.Meta.DocumentID,
		}

		req.Meta.Collect = collect
	}

	if req.Meta.Revocation == nil {
		req.Meta.Revocation = &model.Revocation{
			ID: req.Meta.DocumentID,
		}
	} else {
		if req.Meta.Revocation.ID == "" {
			req.Meta.Revocation.ID = req.Meta.DocumentID
		}
	}

	credentialOfferParameter := openid4vci.CredentialOfferParameters{
		CredentialIssuer: c.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{
			req.Meta.Scope,
		},
		Grants: map[string]any{
			"authorization_code": openid4vci.GrantAuthorizationCode{
				IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", req.Meta.Collect.ID, req.Meta.VCT, req.Meta.AuthenticSource),
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
		qr, err = credentialOffer.QR(c.cfg.Common.CredentialOfferQR.QR.RecoveryLevel, c.cfg.Common.CredentialOfferQR.QR.Size, "", c.cfg.APIGW.CredentialOffers.IssuerURL)
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

	if req.Meta.Collect == nil || req.Meta.Collect.ID == "" {
		collect := &model.Collect{
			ID: req.Meta.DocumentID,
		}

		req.Meta.Collect = collect
	}

	if req.Meta.Revocation == nil {
		req.Meta.Revocation = &model.Revocation{
			ID: req.Meta.DocumentID,
		}
	} else {
		if req.Meta.Revocation.ID == "" {
			req.Meta.Revocation.ID = req.Meta.DocumentID
		}
	}

	upload := &model.CompleteDocument{
		Meta:                req.Meta,
		DocumentDisplay:     req.DocumentDisplay,
		DocumentData:        req.DocumentData,
		DocumentDataVersion: req.DocumentDataVersion,
		Identities:          req.Identities,
		QR:                  qr,
	}

	if err := helpers.ValidateDocumentData(ctx, upload, c.log); err != nil {
		c.log.Error(err, "failed to validate document data")
		return err
	}

	if upload.Identities == nil {
		upload.Identities = []model.Identity{}
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
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		vcclient.NotificationRequest		true	" "
//	@Router			/notification [post]
func (c *Client) Notification(ctx context.Context, req *vcclient.NotificationRequest) (*vcclient.NotificationReply, error) {
	qrCode, err := c.datastoreStore.GetQR(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		VCT:             req.VCT,
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

// IdentityMappingIdentity is the identity input for the mapping endpoint.
// Unlike model.Identity, authentic_source_person_id is not required here because
// the purpose of identity mapping is to look it up from the other identity fields.
type IdentityMappingIdentity struct {
	Schema *model.IdentitySchema `json:"schema" validate:"required"`

	FamilyName string `json:"family_name" validate:"required,min=1,max=100,printascii"`
	GivenName  string `json:"given_name" validate:"required,min=1,max=100,printascii"`
	BirthDate  string `json:"birth_date" validate:"required,datetime=2006-01-02,printascii"`

	BirthPlace                  string   `json:"birth_place,omitempty" validate:"omitempty,min=2,max=100,printascii"`
	Nationality                 []string `json:"nationality,omitempty" validate:"omitempty,dive,iso3166_1_alpha2"`
	PersonalAdministrativeNumber string  `json:"personal_administrative_number,omitempty" validate:"omitempty,min=4,max=50,printascii"`
	BirthFamilyName             string   `json:"birth_family_name,omitempty" validate:"omitempty,min=1,max=100,printascii"`
	BirthGivenName              string   `json:"birth_given_name,omitempty" validate:"omitempty,min=1,max=100,printascii"`
	Sex                         string   `json:"sex,omitempty" validate:"omitempty,oneof=0 1 2 3 4 5 6 7 8 9"`
	EmailAddress                string   `json:"email_address,omitempty" validate:"omitempty,email"`
	MobilePhoneNumber           string   `json:"mobile_phone_number,omitempty" validate:"omitempty,e164"`
	IssuingAuthority            string   `json:"issuing_authority,omitempty" validate:"omitempty,printascii"`
	IssuingCountry              string   `json:"issuing_country,omitempty" validate:"omitempty,iso3166_1_alpha2"`
}

// IdentityMappingRequest is the request for IDMapping
type IdentityMappingRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string                   `json:"authentic_source" validate:"required,max=128,printascii"`
	Identity        *IdentityMappingIdentity `json:"identity" validate:"required"`
}

// IdentityMappingReply is the reply for a IDMapping
type IdentityMappingReply struct {
	Data *model.IDMapping `json:"data"`
}

// IdentityMapping return a mapping between PID and AuthenticSource
//
//	@Summary		IdentityMapping
//	@ID				identity-mapping
//	@Description	Identity mapping endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IdentityMappingReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		IdentityMappingRequest	true	" "
//	@Router			/identity/mapping [post]
func (c *Client) IdentityMapping(ctx context.Context, reg *IdentityMappingRequest) (*IdentityMappingReply, error) {
	identity := &model.Identity{
		Schema:                       reg.Identity.Schema,
		FamilyName:                   reg.Identity.FamilyName,
		GivenName:                    reg.Identity.GivenName,
		BirthDate:                    reg.Identity.BirthDate,
		BirthPlace:                   reg.Identity.BirthPlace,
		Nationality:                  reg.Identity.Nationality,
		PersonalAdministrativeNumber: reg.Identity.PersonalAdministrativeNumber,
		BirthFamilyName:              reg.Identity.BirthFamilyName,
		BirthGivenName:               reg.Identity.BirthGivenName,
		Sex:                          reg.Identity.Sex,
		EmailAddress:                 reg.Identity.EmailAddress,
		MobilePhoneNumber:            reg.Identity.MobilePhoneNumber,
		IssuingAuthority:             reg.Identity.IssuingAuthority,
		IssuingCountry:               reg.Identity.IssuingCountry,
	}
	authenticSourcePersonID, err := c.datastoreStore.IDMapping(ctx, &db.IDMappingQuery{
		AuthenticSource: reg.AuthenticSource,
		Identity:        identity,
	})
	if err != nil {
		return nil, err
	}

	reply := &IdentityMappingReply{
		Data: &model.IDMapping{
			AuthenticSourcePersonID: authenticSourcePersonID,
		},
	}

	return reply, nil
}

// AddDocumentIdentityRequest is the request for DocumentIdentity
type AddDocumentIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" validate:"required"`

	// required: true
	// example: urn:eudi:pid:1
	VCT string `json:"vct" validate:"required"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" validate:"required"`

	Identities []*model.Identity `json:"identities" validate:"required"`
}

// AddDocumentIdentity adds an identity to a document
//
//	@Summary		AddDocumentIdentity
//	@ID				add-document-identity
//	@Description	Adding array of identities to one document
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		AddDocumentIdentityRequest	true	" "
//	@Router			/document/identity [put]
func (c *Client) AddDocumentIdentity(ctx context.Context, req *AddDocumentIdentityRequest) error {
	err := c.datastoreStore.AddDocumentIdentity(ctx, &db.AddDocumentIdentityQuery{
		AuthenticSource: req.AuthenticSource,
		VCT:             req.VCT,
		DocumentID:      req.DocumentID,
		Identities:      req.Identities,
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
	// example: urn:eudi:pid:1
	VCT string `json:"vct" validate:"required"`

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
		VCT:                     req.VCT,
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
	// example: urn:eudi:pid:1
	VCT string `json:"vct" validate:"required"`
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
		VCT:             req.VCT,
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
	VCT             string `json:"vct" validate:"required"`
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
			VCT:             req.VCT,
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
	VCT             string          `json:"vct"`
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
		VCT:             req.VCT,
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

// GetDocumentCollectIDRequest is the request for GetDocumentAttestation
type GetDocumentCollectIDRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	VCT             string          `json:"vct" validate:"required"`
	CollectID       string          `json:"collect_id" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
}

// GetDocumentCollectIDReply is the reply for a generic document
type GetDocumentCollectIDReply struct {
	Data *model.Document `json:"data"`
}

// GetDocumentCollectID return a specific document ??
//
//	@Summary		GetDocumentByCollectID
//	@ID				get-document-collect-id
//	@Description	Get one document with collect id
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetDocumentCollectIDReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		GetDocumentCollectIDRequest	true	" "
//	@Router			/document/collect_id [post]
func (c *Client) GetDocumentCollectID(ctx context.Context, req *GetDocumentCollectIDRequest) (*GetDocumentCollectIDReply, error) {
	query := &db.GetDocumentCollectIDQuery{
		Identity: req.Identity,
		Meta: &model.MetaData{
			AuthenticSource: req.AuthenticSource,
			VCT:             req.VCT,
			Collect: &model.Collect{
				ID: req.CollectID,
			},
		},
	}

	doc, err := c.datastoreStore.GetDocumentCollectID(ctx, query)
	if err != nil {
		c.log.Error(err, "failed to get document")
		return nil, err
	}

	reply := &GetDocumentCollectIDReply{
		Data: doc,
	}
	return reply, nil
}

// RevokeDocumentRequest is the request for RevokeDocument
type RevokeDocumentRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required"`
	VCT             string            `json:"vct" validate:"required"`
	Revocation      *model.Revocation `json:"revocation" validate:"required"`
}

// RevokeDocument revokes a specific document
//
//	@Summary		RevokeDocument
//	@ID				revoke-document
//	@Description	Revoke one document
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		RevokeDocumentRequest	true	" "
//	@Router			/document/revoke [post]
func (c *Client) RevokeDocument(ctx context.Context, req *RevokeDocumentRequest) error {
	ctx, span := c.tracer.Start(ctx, "db:apigw:datastore:revoke")
	defer span.End()

	if req.Revocation.ID == "" {
		return helpers.ErrNoRevocationID
	}

	doc, err := c.datastoreStore.GetByRevocationID(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		VCT:             req.VCT,
		Revocation:      &model.Revocation{ID: req.Revocation.ID},
	})
	if err != nil {
		return err
	}
	c.log.Debug("Document found", "document_id", doc.Meta.DocumentID)

	doc.Meta.Revocation = req.Revocation

	if req.Revocation.RevokedAt == 0 {
		doc.Meta.Revocation.RevokedAt = time.Now().Unix()
		doc.Meta.Revocation.Revoked = true
	}

	if err := c.datastoreStore.Replace(ctx, doc); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "replace failed")
		return err
	}
	c.log.Debug("Document enqueued for update", "document_id", doc.Meta.DocumentID)

	return nil
}

// SearchDocuments search for documents
func (c *Client) SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error) {
	docs, hasMore, err := c.datastoreStore.SearchDocuments(ctx, &db.SearchDocumentsQuery{
		AuthenticSource: req.AuthenticSource,
		VCT:             req.VCT,
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
