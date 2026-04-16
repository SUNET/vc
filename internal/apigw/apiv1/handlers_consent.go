package apiv1

import (
	"context"
	"time"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"
)

// AddConsentRequest is the request for AddConsent
type AddConsentRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
	ConsentTo               string `json:"consent_to" validate:"required,max=128,printascii"`
	SessionID               string `json:"session_id" validate:"required,max=128,printascii"`
}

// AddConsent adds a consent to a document
//
//	@Summary		AddConsent
//	@ID				add-consent
//	@Description	Add consent endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		AddConsentRequest		true	" "
//	@Router			/consent [post]
func (c *Client) AddConsent(ctx context.Context, req *AddConsentRequest) error {
	err := c.db.VCConsentColl.Add(ctx, &db.AddConsentQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		Consent: &model.Consent{
			ConsentTo: req.ConsentTo,
			SessionID: req.SessionID,
			CreatedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// GetConsentRequest is the request for GetConsent
type GetConsentRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required,max=128,printascii"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required,max=128,printascii"`
}

// GetConsent gets a consent for a document
//
//	@Summary		GetConsent
//	@ID				get-consent
//	@Description	Get consent endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	model.Consent			"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		GetConsentRequest		true	" "
//	@Router			/consent/get [post]
func (c *Client) GetConsent(ctx context.Context, req *GetConsentRequest) (*model.Consent, error) {
	res, err := c.db.VCConsentColl.Get(ctx, &db.GetConsentQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}
