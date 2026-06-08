package apiv1

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/google/uuid"
)

// OAuthPar implements OAuth 2.0 Pushed Authorization Request (PAR)
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint
//
//	@Summary		Pushed Authorization Request
//	@ID				oauth-par
//	@Description	Handle OAuth2 Pushed Authorization Request (PAR)
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		openid4vci.PARRequest	true	"PAR request"
//	@Success		201		{object}	openid4vci.ParResponse	"Created"
//	@Failure		400		{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/op/par [post]
func (c *Client) OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error) {
	c.log.Debug("OAuthPar", "req", req)
	oauthClient, err := c.cfg.APIGW.Delivery.OpenID4VCI.Clients.Allow(req.ClientID, req.RedirectURI, req.Scope)
	if err != nil {
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient, err.Error(), 401, err)
	}

	// Public clients MUST use PKCE (RFC 6749 Section 2.1)
	if oauthClient.Type == oauth2.ClientTypePublic && req.CodeChallenge == "" {
		return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidRequest, "code_challenge is required for public clients", 400)
	}

	c.log.Debug("par")

	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuid.NewString())

	c.log.Debug("PAR", "state", req.State)

	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	azt := cache.AuthorizationContext{
		SessionID:            uuid.NewString(),
		Code:                 uuid.NewString(),
		RequestURI:           requestURI,
		Scopes:               []string{req.Scope},
		AuthorizationDetails: req.AuthorizationDetails,
		Forfeited:            false,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		State:                req.State,
		ClientID:             fmt.Sprintf("x509_san_dns:%s", host),
		WalletClientID:       req.ClientID,
		WalletURI:            req.RedirectURI,
		ExpiresAt:            time.Now().Add(60 * time.Second).Unix(),
	}

	azt.Nonce, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	azt.EphemeralEncryptionKeyID, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	azt.VerifierResponseCode, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate response code: %w", err)
	}

	if err := c.cacheService.AuthContext.Save(ctx, &azt); err != nil {
		return nil, err
	}

	reply := &openid4vci.ParResponse{
		RequestURI: requestURI,
		ExpiresIn:  60,
	}

	return reply, nil
}

// OAuthAuthorize handles the OAuth2 authorization endpoint
//
//	@Summary		OAuth2 Authorize
//	@ID				oauth-authorize
//	@Description	Handle OAuth2 authorization request and redirect to consent
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request_uri	query	string	true	"PAR request URI"
//	@Success		302			"Redirect to consent"
//	@Failure		400			{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/authorize [get]
func (c *Client) OAuthAuthorize(ctx context.Context, req *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error) {
	c.log.Debug("Authorize", "req", req)
	host, err := helpers.HostFromURL(c.cfg.APIGW.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	query := &cache.AuthorizationContext{
		RequestURI: req.RequestURI,
		ClientID:   fmt.Sprintf("x509_san_dns:%s", host),
	}
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, query)
	c.log.Debug("Get authorization", "query", query, "authorization", authorizationContext)
	if err != nil {
		c.log.Error(err, "get error")
		return nil, err
	}
	c.log.Debug("Authorization", "state", authorizationContext.State)

	if authorizationContext.ExpiresAt > 0 && time.Now().Unix() > authorizationContext.ExpiresAt {
		c.log.Debug("Authorization context expired")
		return nil, oauth2.ErrExpiredRequest
	}

	if authorizationContext.Forfeited {
		c.log.Debug("Authorization already used")
		return nil, errors.New("not allowed")
	}

	var redirectURL string
	if !authorizationContext.Consent {
		redirectURL = "/authorization/consent"
	}

	reply := &openid4vci.AuthorizationResponse{
		RedirectURL:    redirectURL,
		Scope:          authorizationContext.Scopes[0],
		SessionID:      authorizationContext.SessionID,
		ClientID:       authorizationContext.ClientID,
		WalletClientID: authorizationContext.WalletClientID,
	}

	c.log.Debug("Authorize", "authorization", authorizationContext)

	return reply, nil
}

// OAuthToken implements OAuth 2.0 token endpoint for credential issuance
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint
//
//	@Summary		OAuth2 Token
//	@ID				oauth-token
//	@Description	Exchange authorization code for tokens
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		openid4vci.TokenRequest		true	"Token request"
//	@Success		200		{object}	openid4vci.TokenResponse	"Success"
//	@Failure		400		{object}	helpers.ErrorResponse		"Bad Request"
//	@Router			/token [post]
func (c *Client) OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error) {
	c.log.Debug("OAuthToken", "req", req)

	isPreAuthFlow := req.GrantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	// Resolve the code to look up based on grant type.
	// Field presence is enforced by required_if validation tags on TokenRequest.
	code := req.Code
	if isPreAuthFlow {
		code = req.PreAuthorizedCode
	}

	// Look up the client to enforce type-specific requirements (client_id is optional for pre-auth flow)
	var oauthClient *oauth2.Client
	if req.ClientID != "" {
		var err error
		oauthClient, err = c.cfg.APIGW.Delivery.OpenID4VCI.Clients.Get(req.ClientID)
		if err != nil {
			c.log.Error(err, "client validation failed")
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidClient,
				"Client authentication failed", 401, err)
		}
	}

	// Public clients (wallets) MUST use PKCE per RFC 6749 Section 2.1 — but only for authorization_code grant
	if !isPreAuthFlow && oauthClient != nil && oauthClient.Type == oauth2.ClientTypePublic && req.CodeVerifier == "" {
		return nil, oauth2.OAuthErrPKCERequired
	}

	// Validate DPoP BEFORE consuming the authorization code (RFC 9449 §4).
	// This ensures a stolen code cannot be consumed without a valid DPoP proof.
	var dpopThumbprint string
	if req.DPOP != "" {
		dpop, dpopErr := oauth2.ValidateAndParseDPoPJWT(req.DPOP)
		if dpopErr != nil {
			c.log.Error(dpopErr, "dpop validation error")
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidDPoPProof,
				dpopErr.Error(), 400, dpopErr)
		}

		unique, err := c.cacheService.DPopJTI.SetNX(ctx, dpop.JTI, true)
		if err != nil {
			c.log.Error(err, "DPoP JTI cache error", "jti", dpop.JTI)
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
				"internal error checking DPoP JTI", 500, err)
		}
		if !unique {
			c.log.Error(nil, "DPoP JTI replay detected", "jti", dpop.JTI)
			return nil, oauth2.OAuthErrJTIReplay
		}

		// Validate HTU matches token endpoint
		if dpop.HTU != c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
				fmt.Sprintf("invalid htu: expected %s, got %s", c.cfg.APIGW.Delivery.OpenID4VCI.TokenEndpoint, dpop.HTU), 400)
		}

		// Validate HTM is POST (token endpoint only accepts POST)
		if dpop.HTM != "POST" {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidDPoPProof,
				fmt.Sprintf("invalid htm: expected POST, got %s", dpop.HTM), 400)
		}

		c.log.Debug("DPoP claims", "jti", dpop.JTI, "htu", dpop.HTU, "htm", dpop.HTM)
		dpopThumbprint = dpop.Thumbprint
	} else if !isPreAuthFlow {
		return nil, oauth2.OAuthErrDPoPRequired
	}
	// NOTE: For pre-authorized_code flow, DPoP is optional per OID4VCI §4.1.1.
	// When DPoP is absent, dpopThumbprint remains empty. The credential endpoint
	// (verifyDPoPKeyBinding) skips key-binding verification when the stored
	// thumbprint is empty — see handlers_issuer.go verifyDPoPKeyBinding().
	// Security: the one-time pre-authorized code and (optionally) tx_code provide
	// the primary security mechanism for this flow.
	// TODO: Consider requiring DPoP for pre-auth flow to achieve sender-constrained
	// tokens across all flows (RFC 9449).

	// Verify client_id and redirect_uri BEFORE consuming the authorization code
	// (RFC 6749 §4.1.3). A mismatched client_id must not burn the code, otherwise
	// an attacker with a stolen code could invalidate it for the legitimate client.
	if !isPreAuthFlow {
		preCheck, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{Code: code})
		if err != nil {
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
				"Authorization code is invalid or has already been used", 400, err)
		}
		if preCheck.WalletClientID != "" && req.ClientID != preCheck.WalletClientID {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
				"client_id does not match the authorization request", 400)
		}
		if preCheck.WalletURI != "" && req.RedirectURI != preCheck.WalletURI {
			return nil, oauth2.NewOAuthError(oauth2.ErrCodeInvalidGrant,
				"redirect_uri does not match the authorization request", 400)
		}
	}

	// Now consume the authorization code (after DPoP and client binding are validated)
	authorizationContext, err := c.cacheService.AuthContext.ForfeitAuthorizationCode(ctx, &cache.AuthorizationContext{
		Code: code,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
			"Authorization code is invalid or has already been used", 400, err)
	}
	c.log.Debug("Token", "state", authorizationContext.State)

	if authorizationContext.ExpiresAt > 0 && time.Now().Unix() > authorizationContext.ExpiresAt {
		c.log.Debug("Authorization context expired")
		return nil, oauth2.OAuthErrExpiredRequest
	}

	// Verify PKCE code_challenge (skip for pre-authorized code flow)
	if !isPreAuthFlow {
		if err := oauth2.ValidatePKCE(req.CodeVerifier, authorizationContext.CodeChallenge, authorizationContext.CodeChallengeMethod); err != nil {
			c.log.Error(err, "PKCE validation failed")
			return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidGrant,
				"PKCE validation failed", 400, err)
		}
		c.log.Debug("PKCE validation successful")
	}

	// generating a new access token
	accessToken, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	c.log.Debug("Generated access token", "access_token", accessToken)

	// Bind the public key to the generated access token

	reply := &openid4vci.TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "DPoP",
		ExpiresIn:       3600, // 1 hour
		Scope:           authorizationContext.Scopes[0],
		State:           authorizationContext.State,
		CNonce:          authorizationContext.Nonce,
		CNonceExpiresIn: 3600,
	}

	// Per OID4VCI 1.0 Section 6.2: authorization_details is REQUIRED in the Token Response when
	// authorization_details was used in the Authorization Request, with credential_identifiers added.
	if len(authorizationContext.AuthorizationDetails) > 0 {
		responseDetails := make([]openid4vci.AuthorizationDetailsParameter, len(authorizationContext.AuthorizationDetails))
		for i, ad := range authorizationContext.AuthorizationDetails {
			responseDetails[i] = ad
			responseDetails[i].CredentialIdentifiers = []string{uuid.NewString()}
		}
		reply.AuthorizationDetails = responseDetails
	}

	tokenDoc := &cache.Token{
		AccessToken:    accessToken,
		ExpiresAt:      time.Now().Add(time.Duration(reply.ExpiresIn) * time.Second).Unix(),
		DPoPThumbprint: dpopThumbprint,
	}

	if err := c.cacheService.AuthContext.AddToken(ctx, authorizationContext.Code, tokenDoc); err != nil {
		c.log.Error(err, "failed to add token")
		return nil, err
	}

	c.log.Debug("OAuthToken complete")
	return reply, nil
}

// OAuthMetadata returns the OAuth2 authorization server metadata
//
//	@Summary		OAuth2 Server Metadata
//	@ID				oauth-metadata
//	@Description	Returns the OAuth2 authorization server metadata (RFC 8414)
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	oauth2.AuthorizationServerMetadata	"Success"
//	@Router			/.well-known/oauth-authorization-server [get]
func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	// Shallow-copy to avoid mutating the shared struct concurrently.
	metadata := *c.oauth2Metadata

	// Use cached signed metadata (refreshed by background ticker every 55 min).
	// signed_metadata is OPTIONAL per RFC 8414 — if signing fails
	// (issuer unreachable, not configured, etc.) return unsigned metadata.
	signedMetadata, err := c.getOrSignMetadata(ctx, signedMetadataKeyOAuth2, c.oauth2Metadata, "oauth2-authorization-server", c.oauth2Metadata.Issuer)
	if err != nil {
		c.log.Error(err, "signed_metadata unavailable, serving unsigned metadata")
		metadata.SignedMetadata = ""
	} else {
		metadata.SignedMetadata = signedMetadata
	}

	if err := helpers.Check(ctx, c.cfg, &metadata, c.log); err != nil {
		c.log.Error(err, "metadata check error")
		return nil, err
	}

	return &metadata, nil
}

// JWKSResponse represents a JSON Web Key Set (RFC 7517 §5).
type JWKSResponse = apiv1_issuer.Keys

// JWKS returns the issuer's public signing keys as a JWK Set.
// The keys are fetched from the issuer via gRPC and stripped of any private
// key material before being served.
//
//	@Summary		JWKS
//	@ID				jwks
//	@Description	Returns the JSON Web Key Set for signature verification
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	JWKSResponse	"Success"
//	@Router			/jwks [get]
func (c *Client) JWKS(ctx context.Context) (*JWKSResponse, error) {
	c.log.Debug("JWKS request")

	issuerReply, err := c.issuerClient.JWKS(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from issuer: %w", err)
	}

	reply := issuerReply.GetJwks()
	if reply == nil {
		reply = &apiv1_issuer.Keys{}
	}

	// Strip private key material — only public keys are served
	for _, key := range reply.GetKeys() {
		key.D = ""
		key.KeyOps = nil
		key.Ext = false
	}

	return reply, nil
}

// SDJWTVCIssuerMetadataResponse represents JWT VC Issuer Metadata per SD-JWT VC §5.3.
type SDJWTVCIssuerMetadataResponse struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// SDJWTVCIssuerMetadata returns the JWT VC Issuer Metadata per draft-ietf-oauth-sd-jwt-vc §5.3.
// This metadata is served at /.well-known/jwt-vc-issuer and allows verifiers to discover
// the issuer's JWKS endpoint.
//
//	@Summary		SD-JWT VC Issuer Metadata
//	@ID				sdjwtvc-issuer-metadata
//	@Description	Returns the SD-JWT VC issuer metadata
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	SDJWTVCIssuerMetadataResponse	"Success"
//	@Router			/.well-known/jwt-vc-issuer [get]
func (c *Client) SDJWTVCIssuerMetadata(ctx context.Context) (*SDJWTVCIssuerMetadataResponse, error) {
	c.log.Debug("sd-jwt-vc issuer metadata request")

	reply := &SDJWTVCIssuerMetadataResponse{
		Issuer:  c.cfg.APIGW.PublicURL,
		JWKSURI: c.cfg.APIGW.PublicURL + "/jwks",
	}

	return reply, nil
}

type OauthAuthorizationConsentRequest struct {
	// AuthMethod string `json:"-"`
	SessionID string `json:"-"`
}

type OAuthAuthorizationConsentResponse struct {
	RedirectURL       string
	VerifierContextID string `json:"-"`
}

// OAuthAuthorizationConsent handles the authorization consent flow
//
//	@Summary		Authorization Consent
//	@ID				oauth-authorization-consent
//	@Description	Handles the authorization consent flow for credential issuance
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	OAuthAuthorizationConsentResponse	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse				"Bad Request"
//	@Router			/authorization/consent [get]
func (c *Client) OAuthAuthorizationConsent(ctx context.Context, req *OauthAuthorizationConsentRequest) (*OAuthAuthorizationConsentResponse, error) {
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: req.SessionID})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}
	c.log.Debug("Authorization/consent", "state", authorizationContext.State)

	c.log.Debug("OAuthAuthorizationConsent request")

	verifierRequestURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/request-object")
	if err != nil {
		c.log.Error(err, "failed to construct request URI URL")
		return nil, err
	}
	requestURL, err := url.Parse(verifierRequestURI)
	if err != nil {
		c.log.Error(err, "failed to parse request URI URL")
		return nil, err
	}

	requestURI := url.Values{
		"id": []string{authorizationContext.VerifierResponseCode},
	}

	requestURL.RawQuery = requestURI.Encode()
	finalRequestURI := requestURL.String()

	walletURL, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse wallet URL")
		return nil, err
	}
	values := url.Values{
		"client_id":   []string{authorizationContext.ClientID},
		"request_uri": []string{finalRequestURI},
	}

	walletURL.RawQuery = values.Encode()

	reply := &OAuthAuthorizationConsentResponse{
		RedirectURL:       walletURL.String(),
		VerifierContextID: authorizationContext.VerifierResponseCode,
	}

	c.log.Debug("OAuthAuthorizationConsent response", "redirectURL", reply.RedirectURL)

	return reply, nil
}

type OauthAuthorizationConsentCallbackRequest struct {
	ResponseCode string `json:"response_code" form:"response_code" uri:"response_code"`
}

type OAuthAuthorizationConsentCallbackResponse struct {
	// RedirectURL string `json:"-"`
}

// OAuthAuthorizationConsentCallback handles the consent callback
//
//	@Summary		Authorization Consent Callback
//	@ID				oauth-authorization-consent-callback
//	@Description	Handles the callback after user consents to credential issuance
//	@Tags			OAuth
//	@Produce		json
//	@Success		302	"Redirect"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Router			/authorization/consent/callback [get]
func (c *Client) OAuthAuthorizationConsentCallback(ctx context.Context, req *OauthAuthorizationConsentCallbackRequest) (*OAuthAuthorizationConsentCallbackResponse, error) {
	c.log.Debug("OAuthAuthorizationConsentCallback request", "req", req)
	reply := &OAuthAuthorizationConsentCallbackResponse{}

	return reply, nil
}
