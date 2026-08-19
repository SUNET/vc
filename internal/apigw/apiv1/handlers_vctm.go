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

	"github.com/SUNET/vc/pkg/mdoc"
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
	c.log.Debug("UICreateCredentialOffer", "scope", req.Scope, "wallet_id", req.WalletID)
	vctmReq := &GetVCTMFromScopeRequest{
		Scope: req.Scope,
	}

	// mso_mdoc scopes have no VCTM by design (ErrScopeIsMDoc) - fall back to
	// the MDDL schema for display name/id, same as every other caller of
	// GetVCTMFromScope is expected to per its own doc comment. Without this,
	// the offer-creation UI 500s for every mdoc scope even though issuance
	// itself works fine via GetMDDLFromScope elsewhere.
	var offerName, offerID string
	vctm, err := c.GetVCTMFromScope(ctx, vctmReq)
	switch {
	case err == nil:
		offerName = vctm.Name
		offerID = vctm.VCT
	case errors.Is(err, ErrScopeIsMDoc):
		mddl, mddlErr := c.GetMDDLFromScope(ctx, &GetMDDLFromScopeRequest{Scope: req.Scope})
		if mddlErr != nil {
			return nil, mddlErr
		}
		if len(mddl.Display) > 0 {
			offerName = mddl.Display[0].Name
		}
		if offerName == "" {
			offerName = mddl.DocType
		}
		offerID = mddl.DocType
	default:
		return nil, err
	}

	offerParams := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{req.Scope},
		Grants: map[string]any{
			"authorization_code": map[string]any{},
		},
	}

	credentialOffer, err := offerParams.CredentialOffer()
	if err != nil {
		return nil, err
	}

	wallet, ok := c.cfg.APIGW.Delivery.CredentialOffers.Wallets[req.WalletID]
	if !ok {
		err := errors.New("invalid wallet id")
		return nil, err
	}

	credentialOfferURL := fmt.Sprintf("%s?%s", wallet.RedirectURI, credentialOffer)
	c.log.Debug("UICreateCredentialOffer: offer created", "scope", req.Scope, "wallet_redirect_uri", wallet.RedirectURI, "issuer_url", c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL)

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
		Name: offerName,
		ID:   offerID,
		QR:   *qr,
	}

	return reply, nil
}

// ErrScopeIsMDoc is returned by GetVCTMFromScope when the scope is an
// mso_mdoc credential, which has no VCTM by design. Callers that treat this
// as an expected, non-error condition (e.g. to fall back to
// GetMDDLFromScope) should check for it with errors.Is; callers for whom a
// missing VCTM is itself an error (e.g. no SVG-template concept exists for
// mso_mdoc) can surface it directly.
var ErrScopeIsMDoc = errors.New("scope is an mso_mdoc credential (no VCTM)")

type GetVCTMFromScopeRequest struct {
	Scope string `validate:"required"`
}

func (c *Client) GetVCTMFromScope(ctx context.Context, req *GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	credMeta, ok := c.cfg.Common.CredentialMetadata[req.Scope]
	if !ok {
		err := errors.New("scope is not valid credential")
		return nil, err
	}

	vctm := credMeta.GetVCTM()
	if vctm == nil {
		if credMeta.GetMDDL() != nil {
			return nil, ErrScopeIsMDoc
		}
		return nil, fmt.Errorf("VCTM not loaded for scope: %s", req.Scope)
	}

	return vctm, nil
}

type GetMDDLFromScopeRequest struct {
	Scope string `validate:"required"`
}

// GetMDDLFromScope returns the MDDL schema for a scope, or (nil, nil) when
// the scope is sd-jwt/VCTM-based instead - mirrors GetVCTMFromScope.
func (c *Client) GetMDDLFromScope(ctx context.Context, req *GetMDDLFromScopeRequest) (*mdoc.MDDLSchema, error) {
	credMeta, ok := c.cfg.Common.CredentialMetadata[req.Scope]
	if !ok {
		return nil, errors.New("scope is not valid credential")
	}

	mddl := credMeta.GetMDDL()
	if mddl == nil && credMeta.GetVCTM() == nil {
		return nil, fmt.Errorf("MDDL not loaded for scope: %s", req.Scope)
	}

	return mddl, nil
}

// TypeMetadataRequest holds the request for serving locally-published VCTM.
type TypeMetadataRequest struct {
	Scope string `uri:"scope" validate:"required"`
}

// TypeMetadata returns the raw VCTM JSON for a locally-published scope.
func (c *Client) TypeMetadata(ctx context.Context, req *TypeMetadataRequest) (json.RawMessage, error) {
	constructor := c.cfg.GetCredentialMetadata(req.Scope)
	if constructor == nil {
		return nil, errors.New("unknown scope: " + req.Scope)
	}

	if constructor.IsLocalMDDL() {
		raw := constructor.GetMDDLRaw()
		if raw == nil {
			return nil, errors.New("MDDL not loaded for scope: " + req.Scope)
		}
		return json.RawMessage(raw), nil
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

// SVGTemplateRequest holds the request for fetching an SVG template. Exactly
// one of VCTM or MDDL should be set, mirroring the two credential-metadata
// sources GetVCTMFromScope/GetMDDLFromScope resolve a scope to.
type SVGTemplateRequest struct {
	VCTM *sdjwtvc.VCTM    `json:"-"`
	MDDL *mdoc.MDDLSchema `json:"-"`
}

func (c *Client) SVGTemplateReply(ctx context.Context, req *SVGTemplateRequest) (*vcclient.SVGTemplateReply, error) {
	if req == nil {
		return nil, fmt.Errorf("SVGTemplateRequest is nil")
	}
	if req.VCTM != nil && req.MDDL != nil {
		return nil, fmt.Errorf("SVGTemplateRequest must set exactly one of VCTM or MDDL, not both")
	}

	var svgTemplateURI string
	switch {
	case req.VCTM != nil:
		if len(req.VCTM.Display) == 0 || req.VCTM.Display[0].Rendering == nil ||
			len(req.VCTM.Display[0].Rendering.SVGTemplates) == 0 {
			return nil, fmt.Errorf("VCTM has no SVG templates")
		}
		svgTemplateURI = req.VCTM.Display[0].Rendering.SVGTemplates[0].URI
	case req.MDDL != nil:
		if len(req.MDDL.Display) == 0 || req.MDDL.Display[0].Rendering == nil ||
			len(req.MDDL.Display[0].Rendering.SVGTemplates) == 0 {
			return nil, fmt.Errorf("MDDL schema has no SVG templates")
		}
		svgTemplateURI = req.MDDL.Display[0].Rendering.SVGTemplates[0].URI
	default:
		return nil, fmt.Errorf("no VCTM or MDDL schema provided")
	}

	if cached, ok := c.cacheService.SVGTemplate.Get(ctx, svgTemplateURI); ok {
		reply := &vcclient.SVGTemplateReply{Template: cached}

		return reply, nil
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
		// Validate URL scheme to prevent SSRF (only allow https)
		parsedURL, err := url.Parse(svgTemplateURI)
		if err != nil {
			return nil, fmt.Errorf("invalid SVG template URI: %w", err)
		}
		if parsedURL.Scheme != "https" {
			return nil, errors.New("SVG template URI must use https scheme")
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, svgTemplateURI, nil)
		if err != nil {
			return nil, err
		}

		svgClient := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "https" {
					return errors.New("redirect to non-https scheme not allowed")
				}
				return nil
			},
		}

		response, err := svgClient.Do(httpReq)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			err := errors.New("non ok response code from svg template origin")
			return nil, err
		}

		contentType := response.Header.Get("Content-Type")
		if contentType != "" && !strings.HasPrefix(contentType, "image/svg+xml") {
			return nil, fmt.Errorf("unexpected content type from SVG template origin: %s", contentType)
		}

		const maxSVGSize = 5 * 1024 * 1024 // 5MB
		responseData, err := io.ReadAll(io.LimitReader(response.Body, maxSVGSize))
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
