package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
	"vc/pkg/cache"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UICredentialInfo is a sanitized view of a credential for the UI.
type UICredentialInfo struct {
	VCT        string                         `json:"vct"`
	Attributes map[string]map[string][]string `json:"attributes"`
}

type UIMetadataReply struct {
	Credentials      map[string]*UICredentialInfo `json:"credentials"`
	SupportedWallets map[string]string            `json:"supported_wallets"`
}

func (c *Client) UIMetadata(ctx context.Context) (*UIMetadataReply, error) {
	reply := &UIMetadataReply{
		Credentials:      make(map[string]*UICredentialInfo),
		SupportedWallets: c.cfg.Verifier.SupportedWallets,
	}

	for scope, constructor := range c.cfg.CredentialConstructor {
		info := &UICredentialInfo{
			Attributes: constructor.Attributes,
		}
		if constructor.VCTM != nil {
			info.VCT = constructor.VCTM.VCT
		}
		reply.Credentials[scope] = info
	}

	return reply, nil
}

type UIInteractionRequest struct {
	DCQLQuery *openid4vp.DCQL `json:"dcql_query" validate:"required"`

	// SessionID from http server endpoint
	SessionID string `json:"-"`
}

type UIInteractionReply struct {
	AuthorizationRequest string `json:"authorization_request"`
	QRCode               string `json:"qr_code"`
}

// UIInteraction handles front-end interactions, replying with an Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIInteraction(ctx context.Context, req *UIInteractionRequest) (*UIInteractionReply, error) {
	c.log.Debug("uiInteraction", "dcql_query", req.DCQLQuery)

	nonce := uuid.NewString()
	state := uuid.NewString()
	requestObjectID := uuid.NewString()

	// Use session ID from request if provided, otherwise generate new one
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	// Collect all credential IDs from DCQL query
	scopes := make([]string, 0, len(req.DCQLQuery.Credentials))
	for _, credential := range req.DCQLQuery.Credentials {
		scopes = append(scopes, credential.ID)
	}

	authorizationContext := &cache.AuthorizationContext{
		SessionID:                sessionID,
		Scopes:                   scopes,
		Code:                     "",
		RequestURI:               "",
		WalletURI:                "",
		Forfeited:                false,
		State:                    state,
		ClientID:                 fmt.Sprintf("x509_san_dns:%s", strings.TrimLeft(c.cfg.Verifier.PublicURL, "https://")),
		ExpiresAt:                0,
		CodeChallenge:            "",
		CodeChallengeMethod:      "",
		Consent:                  false,
		AuthenticSource:          "",
		Identity:                 &model.Identity{},
		Token:                    &cache.Token{},
		Nonce:                    nonce,
		EphemeralEncryptionKeyID: uuid.NewString(),
		VerifierResponseCode:     "",
		RequestObjectID:          requestObjectID,
	}

	_, ephemeralPublicJWK, err := c.openid4vp.EphemeralKeyCache.GenerateAndStore(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return nil, err
	}

	responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "verification", "direct_post")
	if err != nil {
		return nil, fmt.Errorf("failed to construct response URI: %w", err)
	}

	requestObject := &openid4vp.RequestObject{
		ResponseURI:  responseURI,
		AUD:          "https://self-issued.me/v2",
		ISS:          strings.TrimLeft(c.cfg.Verifier.PublicURL, "https://"),
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormatsSupported: c.cfg.Verifier.PreferredVPFormats,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationSignedResponseALG:    "",
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT:              time.Now().UTC().Unix(),
		RedirectURI:      "",
		Scope:            "",
		DCQLQuery:        req.DCQLQuery,
		RequestURIMethod: "",
		TransactionData:  []openid4vp.TransactionData{},
		VerifierInfo:     []openid4vp.VerifierInfo{},
	}

	if err := c.cacheService.AuthContext.Save(ctx, authorizationContext); err != nil {
		return nil, err
	}

	c.openid4vp.RequestObjectCache.Set(authorizationContext.RequestObjectID, requestObject)

	reply := &UIInteractionReply{}

	reply.AuthorizationRequest, err = requestObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.PublicURL, requestObjectID)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
