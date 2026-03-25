package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/skip2/go-qrcode"
)

// UICredentialOffers provides data for UI /offer endpoint
func (c *Client) UICredentialOffers(ctx context.Context) (*CredentialOfferLookupMetadata, error) {
	return c.CredentialOfferLookupMetadata, nil
}

type UICredentialOfferRequest struct {
	Scope    string `json:"scope" uri:"scope" binding:"required"`
	WalletID string `json:"wallet_id" uri:"wallet_id" binding:"required"`
}

type CredentialOfferReply struct {
	Name string            `json:"name" validate:"required"`
	ID   string            `json:"id" validate:"required"`
	QR   openid4vp.QRReply `json:"qr" validate:"required"`
}

func (c *Client) UICreateCredentialOffer(ctx context.Context, req *UICredentialOfferRequest) (*CredentialOfferReply, error) {
	vctmReq := &GetVCTMFromScopeRequest{
		Scope: req.Scope,
	}

	vctm, err := c.GetVCTMFromScope(ctx, vctmReq)
	if err != nil {
		return nil, err
	}

	offerParams := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           c.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{req.Scope},
		Grants: map[string]any{
			"authorization_code": map[string]any{},
		},
	}

	credentialOffer, err := offerParams.CredentialOffer()
	if err != nil {
		return nil, err
	}

	wallet, ok := c.cfg.APIGW.CredentialOffers.Wallets[req.WalletID]
	if !ok {
		err := errors.New("invalid wallet id")
		return nil, err
	}

	credentialOfferURL := fmt.Sprintf("%s?%s", wallet.RedirectURI, credentialOffer)

	u, err := url.Parse(credentialOfferURL)
	if err != nil {
		c.log.Error(err, "failed to parse credential offer URL")
		return nil, err
	}

	qr, err := openid4vp.GenerateQR(u, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	reply := &CredentialOfferReply{
		Name: vctm.Name,
		ID:   vctm.VCT,
		QR:   *qr,
	}

	return reply, nil
}

type GetVCTMFromScopeRequest struct {
	Scope string `validate:"required"`
}

func (c *Client) GetVCTMFromScope(ctx context.Context, req *GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	credentialConstructor, ok := c.cfg.Common.CredentialConstructor[req.Scope]
	if !ok {
		err := errors.New("scope is not valid credential")
		return nil, err
	}

	vctm := credentialConstructor.GetVCTM()
	if vctm == nil {
		return nil, fmt.Errorf("VCTM not loaded for scope: %s", req.Scope)
	}

	return vctm, nil
}

// TypeMetadataRequest holds the request for serving locally-published VCTM.
type TypeMetadataRequest struct {
	Scope string `uri:"scope" validate:"required"`
}

// TypeMetadata returns the raw VCTM JSON for a locally-published scope.
func (c *Client) TypeMetadata(ctx context.Context, req *TypeMetadataRequest) (json.RawMessage, error) {
	constructor := c.cfg.GetCredentialConstructor(req.Scope)
	if constructor == nil {
		return nil, errors.New("unknown scope: " + req.Scope)
	}

	if !constructor.IsLocalVCTM() {
		return nil, errors.New("VCTM for scope " + req.Scope + " is not published by this service")
	}

	raw := constructor.GetVCTMRaw()
	if raw == nil {
		return nil, errors.New("VCTM not loaded for scope: " + req.Scope)
	}

	reply := json.RawMessage(raw)

	return reply, nil
}

// SVGTemplateRequest holds the request for fetching an SVG template.
type SVGTemplateRequest struct {
	VCTM *sdjwtvc.VCTM `json:"-"`
}

func (c *Client) SVGTemplateReply(ctx context.Context, req *SVGTemplateRequest) (*vcclient.SVGTemplateReply, error) {
	if len(req.VCTM.Display) == 0 || req.VCTM.Display[0].Rendering == nil ||
		len(req.VCTM.Display[0].Rendering.SVGTemplates) == 0 {
		return nil, fmt.Errorf("VCTM has no SVG templates")
	}

	svgTemplateURI := req.VCTM.Display[0].Rendering.SVGTemplates[0].URI

	if cached, ok := c.cacheService.SVGTemplate.Get(ctx, svgTemplateURI); ok {
		return &vcclient.SVGTemplateReply{Template: cached}, nil
	}

	c.log.Debug("SVG template not available in cache, fetching from origin")

	var template string

	if strings.HasPrefix(svgTemplateURI, "data:") {
		// Handle data: URIs (e.g., data:image/svg+xml;base64,...)
		commaIdx := strings.Index(svgTemplateURI, ",")
		if commaIdx < 0 {
			return nil, errors.New("invalid data URI: missing comma separator")
		}
		header := svgTemplateURI[5:commaIdx] // after "data:"
		data := svgTemplateURI[commaIdx+1:]

		if strings.HasSuffix(header, ";base64") {
			// Data is already base64-encoded
			template = data
		} else {
			// Plain text data URI — base64-encode it
			template = base64.StdEncoding.EncodeToString([]byte(data))
		}
	} else {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, svgTemplateURI, nil)
		if err != nil {
			return nil, err
		}

		response, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			err := errors.New("non ok response code from svg template origin")
			return nil, err
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		template = base64.StdEncoding.EncodeToString([]byte(responseData))
	}

	reply := &vcclient.SVGTemplateReply{
		Template: template,
	}

	c.cacheService.SVGTemplate.SetWithTTL(ctx, svgTemplateURI, reply.Template, 2*time.Hour)

	return reply, nil
}
