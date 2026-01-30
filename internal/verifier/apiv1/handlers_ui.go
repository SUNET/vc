package apiv1

import (
	"context"
	"fmt"
	"strings"
	"time"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type UIMetadataReply struct {
	Credentials      map[string]*model.CredentialConstructor `json:"credentials"`
	SupportedWallets map[string]string                       `json:"supported_wallets"`
}

func (c *Client) UIMetadata(ctx context.Context) (*UIMetadataReply, error) {
	reply := &UIMetadataReply{}
	reply.Credentials = c.cfg.CredentialConstructor

	for _, constructor := range reply.Credentials {
		constructor.AuthMethod = ""
		constructor.VCTMFilePath = ""
		constructor.VCTM = nil
	}

	reply.SupportedWallets = c.cfg.Verifier.SupportedWallets

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

	authorizationContext := &model.AuthorizationContext{
		SessionID:                sessionID,
		Scope:                    scopes,
		Code:                     "",
		RequestURI:               "",
		WalletURI:                "",
		IsUsed:                   false,
		State:                    state,
		ClientID:                 fmt.Sprintf("x509_san_dns:%s", strings.TrimLeft(c.cfg.Verifier.ExternalServerURL, "https://")),
		ExpiresAt:                0,
		CodeChallenge:            "",
		CodeChallengeMethod:      "",
		LastUsed:                 0,
		SavedAt:                  0,
		Consent:                  false,
		AuthenticSource:          "",
		Identity:                 &model.Identity{},
		Token:                    &model.Token{},
		Nonce:                    nonce,
		EphemeralEncryptionKeyID: uuid.NewString(),
		VerifierResponseCode:     "",
		RequestObjectID:          requestObjectID,
	}

	_, ephemeralPublicJWK, err := c.openid4vp.EphemeralKeyCache.GenerateAndStore(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return nil, err
	}

	requestObject := &openid4vp.RequestObject{
		ResponseURI:  fmt.Sprintf("%s/verification/direct_post", c.cfg.Verifier.ExternalServerURL),
		AUD:          "https://self-issued.me/v2",
		ISS:          strings.TrimLeft(c.cfg.Verifier.ExternalServerURL, "https://"),
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

	if err := c.authContextStore.Save(ctx, authorizationContext); err != nil {
		return nil, err
	}

	c.openid4vp.RequestObjectCache.Set(authorizationContext.RequestObjectID, requestObject)

	reply := &UIInteractionReply{}

	reply.AuthorizationRequest, err = requestObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.ExternalServerURL, requestObjectID)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
