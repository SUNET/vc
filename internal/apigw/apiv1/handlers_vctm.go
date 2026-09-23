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

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
)

// UICredentialOffers provides data for UI /offer endpoint
func (c *Client) UICredentialOffers(ctx context.Context) (*CredentialOfferLookupMetadata, error) {
	return c.CredentialOfferLookupMetadata, nil
}

// OpaqueWalletID is a reserved wallet id. The credential offer itself is
// wallet-independent, so the UI no longer selects a wallet before an offer
// is produced; the id stays reserved (rejected at config load, see
// pkg/configuration) so that no configured wallet can collide with the
// opaque "openid-credential-offer://" rendering.
const OpaqueWalletID = "opaque"

type UICredentialOfferRequest struct {
	Scope string `json:"scope" uri:"scope" binding:"required"`
}

// CredentialOfferWalletReply is one configured wallet's rendering of the
// very same offer: the wallet's redirect_uri carrying the offer as its
// query string.
type CredentialOfferWalletReply struct {
	Name string `json:"name" validate:"required"`
	URI  string `json:"uri" validate:"required"`
}

// CredentialOfferReply carries one wallet-independent credential offer in
// every form the issuer UI needs to render it:
//
//	Offer   the bare "credential_offer=..." query string, which is also the
//	        payload the DC API (openid4vci-v1) issuance request is built from
//	URI     the opaque, wallet-agnostic by-value deep link
//	QR      the by-reference ("credential_offer_uri=...") rendering, which is
//	        the one place where offer size actually matters
//	Wallets one entry per configured wallet, same offer, wallet's own prefix
type CredentialOfferReply struct {
	Name    string                                `json:"name" validate:"required"`
	ID      string                                `json:"id" validate:"required"`
	Offer   string                                `json:"offer" validate:"required"`
	URI     string                                `json:"uri" validate:"required"`
	QR      openid4vp.QRReply                     `json:"qr" validate:"required"`
	Wallets map[string]CredentialOfferWalletReply `json:"wallets"`
}

func (c *Client) UICreateCredentialOffer(ctx context.Context, req *UICredentialOfferRequest) (*CredentialOfferReply, error) {
	c.log.Debug("UICreateCredentialOffer", "scope", req.Scope)
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

	// The opaque, wallet-agnostic by-value form. Every configured wallet's
	// rendering below is the exact same offer behind a different prefix -
	// the offer is wallet-independent, only the scheme/host differs.
	credentialOfferURL := fmt.Sprintf("openid-credential-offer://?%s", credentialOffer)

	// The QR is scanned by whatever wallet happens to be on the phone, and
	// it is the one rendering where the size of the encoded payload matters,
	// so it carries the offer by reference rather than by value.
	qrURL, err := c.credentialOfferReferenceURL(ctx, &offerParams)
	if err != nil {
		return nil, err
	}

	// Encoded as built, not round-tripped through url.Parse: the offer URI
	// has an empty authority ("openid-credential-offer://"), which url.URL
	// cannot represent - see GenerateQR's doc comment.
	qr, err := openid4vp.GenerateQR(qrURL, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	wallets := make(map[string]CredentialOfferWalletReply, len(c.cfg.APIGW.Delivery.CredentialOffers.Wallets))
	for id, wallet := range c.cfg.APIGW.Delivery.CredentialOffers.Wallets {
		wallets[id] = CredentialOfferWalletReply{
			Name: wallet.Label,
			URI:  fmt.Sprintf("%s?%s", wallet.RedirectURI, credentialOffer),
		}
	}

	c.log.Debug("UICreateCredentialOffer: offer created",
		"scope", req.Scope,
		"issuer_url", c.cfg.APIGW.Delivery.CredentialOffers.IssuerURL,
		"wallets", len(wallets),
	)

	reply := &CredentialOfferReply{
		Name:    offerName,
		ID:      offerID,
		Offer:   credentialOffer.String(),
		URI:     credentialOfferURL,
		QR:      *qr,
		Wallets: wallets,
	}

	return reply, nil
}

// credentialOfferUINamespace is the UUIDv5 namespace for issuer-UI credential
// offers. Fixed for all time: changing it orphans every already-stored offer.
var credentialOfferUINamespace = uuid.MustParse("053b4aae-8b08-46ea-b9c5-3da8ac7a4d82")

// credentialOfferUIUUID derives the by-reference document id from the offer
// itself, so the same offer always maps to the same document.
//
// This is what bounds the size of the credential-offer collection. GET
// /offers/:scope is the operator UI's own endpoint on the unauthenticated
// root group, so a freshly generated id per request would let anyone who can
// reach the issuer grow that collection without limit simply by asking for
// one valid scope in a loop - and a rate limit alone does not fix that, it
// only slows it down. Neither store implementation has an expiry mechanism to
// lean on instead: the Mongo collection indexes uuid only (no TTL index), and
// the SQL credential_offer table has no expiry column, so bounding growth by
// retention time would need a schema change plus something to sweep with.
// Content-addressing bounds it by configuration instead: at most one document
// per distinct offer, which is one per configured scope, however many requests
// arrive. Unknown scopes never reach here - they fail the VCTM/MDDL lookup
// above - so the set of reachable offers is exactly the configured one.
//
// This is safe only because the offer carries no secret: it is an
// authorization_code grant with no issuer_state, byte-identical to the offer
// already embedded in the by-value QR and deep links on the same page. An
// offer carrying a one-time pre-authorized code must keep a fresh,
// unguessable id, which is why the choice is made here and not inside
// CredentialOfferURI.
func credentialOfferUIUUID(offerParams *openid4vci.CredentialOfferParameters) (string, error) {
	raw, err := offerParams.Marshal()
	if err != nil {
		return "", err
	}

	return uuid.NewSHA1(credentialOfferUINamespace, raw).String(), nil
}

// credentialOfferReferenceURL stores the offer under its content-addressed
// UUID and returns the by-reference ("credential_offer_uri=...") deep link
// pointing at it.
//
// The referenced document is served by GET /credential-offer/:credential_offer_uuid
// (VCICredentialOfferURI), which until now had nothing writing to the store
// it reads from.
func (c *Client) credentialOfferReferenceURL(ctx context.Context, offerParams *openid4vci.CredentialOfferParameters) (string, error) {
	offerUUID, err := credentialOfferUIUUID(offerParams)
	if err != nil {
		return "", err
	}

	offerURI, err := offerParams.CredentialOfferURI(c.cfg.APIGW.PublicURL, offerUUID)
	if err != nil {
		return "", err
	}

	if c.credentialOfferStore == nil {
		return "", errors.New("credential offer store not configured")
	}

	// Write only when the document is not already there. uuid is uniquely
	// indexed, so a repeat request would otherwise fail on the duplicate key
	// rather than reuse what is already stored.
	if _, err := c.credentialOfferStore.Get(ctx, offerUUID); err != nil {
		if saveErr := c.credentialOfferStore.Save(ctx, &db.CredentialOfferDocument{
			UUID:                      offerUUID,
			CredentialOfferParameters: *offerParams,
		}); saveErr != nil {
			// A concurrent request may have inserted the same document in
			// between. Its content is identical by construction, so the offer
			// this reply points at is served either way - only a store that
			// still has nothing under this id is a real failure.
			if _, getErr := c.credentialOfferStore.Get(ctx, offerUUID); getErr != nil {
				return "", saveErr
			}
		}
	}

	query := url.Values{"credential_offer_uri": {offerURI.String()}}

	return fmt.Sprintf("openid-credential-offer://?%s", query.Encode()), nil
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

	// Serve whatever document this scope was built from, wherever it came
	// from. For a registry- or URL-resolved type these are the exact bytes
	// vct#integrity in every issued credential is computed over, so a wallet
	// that resolves the type here can verify that pin; refusing to serve them
	// left wallets checking the credential against some other copy of the
	// document, or against none.
	//
	// This does not republish the type under this issuer's own identifier:
	// ResolveVCTUrls still rewrites the vct only for local VCTMs, so an
	// externally-resolved document keeps the vct it arrived with.
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
