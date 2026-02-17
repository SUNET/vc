package apiv1

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"time"
	"vc/internal/verifier/apiv1/utils"
	"vc/internal/verifier/db"
	"vc/pkg/cache"
	"vc/pkg/crypto"
	"vc/pkg/jose"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthorizeRequest represents an OIDC authorization request
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope" binding:"required"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	ResponseMode        string `form:"response_mode"`
	Display             string `form:"display"`
	Prompt              string `form:"prompt"`
	MaxAge              int    `form:"max_age"`
	UILocales           string `form:"ui_locales"`
	IDTokenHint         string `form:"id_token_hint"`
	LoginHint           string `form:"login_hint"`
	ACRValues           string `form:"acr_values"`
}

// AuthorizeResponse represents the response to an authorization request
type AuthorizeResponse struct {
	SessionID        string   `json:"session_id"`
	QRCodeData       string   `json:"qr_code_data"`
	QRCodeImageURL   string   `json:"qr_code_image_url"`
	DeepLinkURL      string   `json:"deep_link_url"`
	PollURL          string   `json:"poll_url"`
	PreferredFormats []string `json:"preferred_formats"`
	UseJAR           bool     `json:"use_jar"`
	ResponseMode     string   `json:"response_mode"`
	Title            string   `json:"title"`
	Subtitle         string   `json:"subtitle"`
	PrimaryColor     string   `json:"primary_color"`
	SecondaryColor   string   `json:"secondary_color"`
	Theme            string   `json:"theme"`
	CustomCSS        string   `json:"custom_css"`
	CSSFile          string   `json:"css_file"`
	LogoURL          string   `json:"logo_url"`
}

// Authorize handles the OIDC authorization request
func (c *Client) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:authorize")
	defer span.End()

	// Validate client
	client, err := c.db.Clients.GetByClientID(ctx, req.ClientID)
	if err != nil {
		c.log.Error(err, "Failed to get client")
		return nil, ErrServerError
	}
	if client == nil {
		c.log.Info("Client not found", "client_id", req.ClientID)
		return nil, ErrInvalidClient
	}

	// Validate redirect URI
	if !utils.ValidateRedirectURI(req.RedirectURI, client.RedirectURIs) {
		c.log.Info("Invalid redirect URI", "redirect_uri", req.RedirectURI)
		return nil, ErrInvalidRequest
	}

	// Validate response type
	if !c.containsOIDC(client.ResponseTypes, req.ResponseType) {
		c.log.Info("Unsupported response type", "response_type", req.ResponseType)
		return nil, ErrInvalidRequest
	}

	// Validate scope
	requestedScopes := strings.Split(req.Scope, " ")
	if !utils.ValidateScopes(requestedScopes, client.AllowedScopes) {
		c.log.Info("Invalid scope requested")
		return nil, ErrInvalidScope
	}

	// Validate PKCE if required
	if client.RequirePKCE && req.CodeChallenge == "" {
		c.log.Info("PKCE required but no code_challenge provided")
		return nil, ErrInvalidRequest
	}

	// Create session
	sessionID, err := crypto.GenerateSecureToken(0, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create DCQL query based on requested scopes
	dcqlQuery, err := c.createDCQLQuery(ctx, requestedScopes)
	if err != nil {
		c.log.Error(err, "Failed to create DCQL query")
		return nil, ErrServerError
	}

	authCtx := &cache.AuthorizationContext{
		SessionID: sessionID,
		CreatedAt: time.Now(),
		// Authorization request expires after the code duration
		ExpiresAt:           time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.CodeDuration) * time.Second).Unix(),
		Status:              cache.SessionStatusPending,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              requestedScopes,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ResponseType:        req.ResponseType,
		ResponseMode:        req.ResponseMode,
		DCQLQuery:           dcqlQuery,
	}

	// Save session
	if err := c.cacheService.AuthContext.Create(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to create session")
		return nil, ErrServerError
	}

	// Generate OpenID4VP authorization request
	requestObjectPath, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/request-object", sessionID)
	if err != nil {
		c.log.Error(err, "Failed to construct request object path")
		return nil, ErrServerError
	}

	// Construct OpenID4VP authorization request URL with query parameters
	q := url.Values{}
	q.Set("client_id", c.cfg.Verifier.PublicURL)
	q.Set("request_uri", requestObjectPath)
	authzReqURL := "openid4vp://?" + q.Encode()

	qrCodeImageURL, err := url.JoinPath("/qr", sessionID)
	if err != nil {
		c.log.Error(err, "Failed to construct QR code image URL")
		return nil, ErrServerError
	}

	pollURL, err := url.JoinPath("/poll", sessionID)
	if err != nil {
		c.log.Error(err, "Failed to construct poll URL")
		return nil, ErrServerError
	}

	// Build response with DC API configuration
	response := &AuthorizeResponse{
		SessionID:      sessionID,
		QRCodeData:     authzReqURL,
		QRCodeImageURL: qrCodeImageURL,
		DeepLinkURL:    authzReqURL,
		PollURL:        pollURL,
	}

	// Add Digital Credentials API configuration
	if c.cfg.Verifier.DigitalCredentials.Enabled {
		response.PreferredFormats = c.cfg.Verifier.DigitalCredentials.PreferredFormats
		response.UseJAR = c.cfg.Verifier.DigitalCredentials.UseJAR
		response.ResponseMode = c.cfg.Verifier.DigitalCredentials.ResponseMode
	} else {
		// Defaults
		response.PreferredFormats = []string{"vc+sd-jwt"}
		response.UseJAR = false
		response.ResponseMode = "direct_post"
	}

	// Add CSS customization configuration
	cssConfig := c.cfg.Verifier.AuthorizationPageCSS
	response.Title = cssConfig.Title
	if response.Title == "" {
		response.Title = "Credential Verification"
	}
	response.Subtitle = cssConfig.Subtitle
	if response.Subtitle == "" {
		response.Subtitle = "Please present your digital credential to continue"
	}
	response.PrimaryColor = cssConfig.PrimaryColor
	if response.PrimaryColor == "" {
		response.PrimaryColor = "#3182ce"
	}
	response.SecondaryColor = cssConfig.SecondaryColor
	if response.SecondaryColor == "" {
		response.SecondaryColor = "#2c5282"
	}
	response.Theme = cssConfig.Theme
	if response.Theme == "" {
		response.Theme = "light"
	}
	response.CustomCSS = cssConfig.CustomCSS
	response.CSSFile = cssConfig.CSSFile
	response.LogoURL = cssConfig.LogoURL

	return response, nil
}

// TokenRequest represents an OIDC token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
	RefreshToken string `form:"refresh_token"`
}

// TokenResponse represents an OIDC token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles the OIDC token request
func (c *Client) Token(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:token")
	defer span.End()

	switch req.GrantType {
	case "authorization_code":
		return c.handleAuthorizationCodeGrant(ctx, req)
	case "refresh_token":
		return c.handleRefreshTokenGrant(ctx, req)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

func (c *Client) handleAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// Get session by authorization code
	authCtx, err := c.cacheService.AuthContext.GetByAuthorizationCode(ctx, req.Code)
	if err != nil {
		c.log.Info("Session not found for code", "error", err)
		return nil, ErrInvalidGrant
	}
	if authCtx == nil {
		c.log.Info("Session not found for code")
		return nil, ErrInvalidGrant
	}

	// Check if code has already been used
	if authCtx.Forfeited {
		c.log.Info("Authorization code already used", "session_id", authCtx.SessionID)
		return nil, ErrInvalidGrant
	}

	// Check if code has expired
	if time.Now().Unix() > authCtx.CodeExpiresAt {
		c.log.Info("Authorization code expired", "session_id", authCtx.SessionID)
		return nil, ErrInvalidGrant
	}

	// Authenticate client
	client, err := c.db.Clients.GetByClientID(ctx, req.ClientID)
	if err != nil {
		c.log.Error(err, "Failed to get client")
		return nil, ErrServerError
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	if err := c.authenticateOIDCClient(client, req.ClientSecret); err != nil {
		c.log.Info("Client authentication failed")
		return nil, ErrInvalidClient
	}

	// Verify client ID matches
	if authCtx.ClientID != req.ClientID {
		c.log.Info("Client ID mismatch")
		return nil, ErrInvalidGrant
	}

	// Verify redirect URI matches
	if authCtx.RedirectURI != req.RedirectURI {
		c.log.Info("Redirect URI mismatch")
		return nil, ErrInvalidGrant
	}

	// Validate PKCE if present
	if authCtx.CodeChallenge != "" {
		if err := utils.ValidatePKCE(req.CodeVerifier, authCtx.CodeChallenge, authCtx.CodeChallengeMethod); err != nil {
			c.log.Info("PKCE validation failed")
			return nil, ErrInvalidGrant
		}
	}

	// Mark code as forfeited
	if err := c.cacheService.AuthContext.MarkCodeAsForfeited(ctx, authCtx.SessionID); err != nil {
		c.log.Error(err, "Failed to forfeit code")
		return nil, ErrServerError
	}
	authCtx.Forfeited = true

	// Generate tokens
	accessToken, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate access token")
		return nil, ErrServerError
	}
	refreshToken, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate refresh token")
		return nil, ErrServerError
	}

	// Generate ID token
	idToken, err := c.generateIDToken(ctx, authCtx, client)
	if err != nil {
		c.log.Error(err, "Failed to generate ID token")
		return nil, ErrServerError
	}

	// Update session with tokens
	authCtx.AccessToken = accessToken
	authCtx.AccessTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.AccessTokenDuration) * time.Second).Unix()
	authCtx.IDToken = idToken
	authCtx.RefreshToken = refreshToken
	authCtx.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.RefreshTokenDuration) * time.Second).Unix()
	authCtx.Status = cache.SessionStatusTokenIssued

	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to update session")
		return nil, ErrServerError
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    c.cfg.Verifier.OIDC.AccessTokenDuration,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        strings.Join(authCtx.Scopes, " "),
	}, nil
}

func (c *Client) handleRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// TODO: Implement refresh token grant
	return nil, ErrUnsupportedGrantType
}

// generateIDToken creates a signed ID token
func (c *Client) generateIDToken(ctx context.Context, authCtx *cache.AuthorizationContext, client *db.Client) (string, error) {
	now := time.Now()

	// Generate subject identifier
	walletID := authCtx.WalletID
	sub := c.generateSubjectIdentifier(walletID, client.ClientID)

	// Get token expiration from config
	idTokenTTL := time.Duration(c.cfg.Verifier.OIDC.IDTokenDuration) * time.Second

	claims := jwt.MapClaims{
		"iss":   c.cfg.Verifier.OIDC.Issuer,
		"sub":   sub,
		"aud":   client.ClientID,
		"exp":   now.Add(idTokenTTL).Unix(),
		"iat":   now.Unix(),
		"nonce": authCtx.Nonce,
	}

	// Add verified claims
	maps.Copy(claims, authCtx.VerifiedClaims)

	// Use jose.MakeJWT to sign with pki.Signer
	header := jwt.MapClaims{
		"typ": "JWT",
	}
	tokenString, err := jose.MakeJWT(ctx, header, claims, c.pkiSigner)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// authenticateOIDCClient validates client credentials for OIDC endpoints
func (c *Client) authenticateOIDCClient(client *db.Client, clientSecret string) error {
	if client.TokenEndpointAuthMethod == "none" {
		return nil // Public client
	}

	if client.ClientSecretHash == "" {
		return errors.New("client secret not configured")
	}

	return bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret))
}
