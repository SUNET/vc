package apiv1

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"vc/internal/verifier/apiv1/utils"
	"vc/internal/verifier/db"
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
	session := &db.Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
		// Session expires after the configured duration
		ExpiresAt: time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.SessionDuration) * time.Second),
		Status:    db.SessionStatusPending,
		OIDCRequest: db.OIDCRequest{
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			Scope:               req.Scope,
			State:               req.State,
			Nonce:               req.Nonce,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			ResponseType:        req.ResponseType,
			ResponseMode:        req.ResponseMode,
			Display:             req.Display,
			Prompt:              req.Prompt,
			MaxAge:              req.MaxAge,
			UILocales:           strings.Split(req.UILocales, " "),
			IDTokenHint:         req.IDTokenHint,
			LoginHint:           req.LoginHint,
			ACRValues:           strings.Split(req.ACRValues, " "),
		},
	}

	// Create DCQL query based on requested scopes
	dcqlQuery, err := c.createDCQLQuery(ctx, requestedScopes)
	if err != nil {
		c.log.Error(err, "Failed to create DCQL query")
		return nil, ErrServerError
	}
	session.OpenID4VP.DCQL = dcqlQuery

	// Save session
	if err := c.db.Sessions.Create(ctx, session); err != nil {
		c.log.Error(err, "Failed to create session")
		return nil, ErrServerError
	}

	// Generate OpenID4VP authorization request
	authzReqURL := fmt.Sprintf("openid4vp://?client_id=%s&request_uri=%s/verification/request-object/%s",
		c.cfg.Verifier.ExternalServerURL,
		c.cfg.Verifier.ExternalServerURL,
		sessionID,
	)

	// Build response with DC API configuration
	response := &AuthorizeResponse{
		SessionID:      sessionID,
		QRCodeData:     authzReqURL,
		QRCodeImageURL: fmt.Sprintf("/qr/%s", sessionID),
		DeepLinkURL:    authzReqURL,
		PollURL:        fmt.Sprintf("/poll/%s", sessionID),
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
	session, err := c.db.Sessions.GetByAuthorizationCode(ctx, req.Code)
	if err != nil {
		c.log.Error(err, "Failed to get session by code")
		return nil, ErrServerError
	}
	if session == nil {
		c.log.Info("Session not found for code")
		return nil, ErrInvalidGrant
	}

	// Check if code has already been used
	if session.Tokens.AuthorizationCodeUsed {
		c.log.Info("Authorization code already used", "session_id", session.ID)
		return nil, ErrInvalidGrant
	}

	// Check if code has expired
	if time.Now().After(session.Tokens.CodeExpiresAt) {
		c.log.Info("Authorization code expired", "session_id", session.ID)
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
	if session.OIDCRequest.ClientID != req.ClientID {
		c.log.Info("Client ID mismatch")
		return nil, ErrInvalidGrant
	}

	// Verify redirect URI matches
	if session.OIDCRequest.RedirectURI != req.RedirectURI {
		c.log.Info("Redirect URI mismatch")
		return nil, ErrInvalidGrant
	}

	// Validate PKCE if present
	if session.OIDCRequest.CodeChallenge != "" {
		if err := utils.ValidatePKCE(req.CodeVerifier, session.OIDCRequest.CodeChallenge, session.OIDCRequest.CodeChallengeMethod); err != nil {
			c.log.Info("PKCE validation failed")
			return nil, ErrInvalidGrant
		}
	}

	// Mark code as used
	if err := c.db.Sessions.MarkCodeAsUsed(ctx, session.ID); err != nil {
		c.log.Error(err, "Failed to mark code as used")
		return nil, ErrServerError
	}
	session.Tokens.AuthorizationCodeUsed = true

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
	idToken, err := c.generateIDToken(ctx, session, client)
	if err != nil {
		c.log.Error(err, "Failed to generate ID token")
		return nil, ErrServerError
	}

	// Update session with tokens
	session.Tokens.AccessToken = accessToken
	session.Tokens.AccessTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.AccessTokenDuration) * time.Second)
	session.Tokens.IDToken = idToken
	session.Tokens.RefreshToken = refreshToken
	session.Tokens.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.RefreshTokenDuration) * time.Second)
	session.Tokens.TokenType = "Bearer"
	session.Status = db.SessionStatusTokenIssued

	if err := c.db.Sessions.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session")
		return nil, ErrServerError
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    c.cfg.Verifier.OIDC.AccessTokenDuration,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        session.OIDCRequest.Scope,
	}, nil
}

func (c *Client) handleRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// TODO: Implement refresh token grant
	return nil, ErrUnsupportedGrantType
}

// generateIDToken creates a signed ID token
func (c *Client) generateIDToken(ctx context.Context, session *db.Session, client *db.Client) (string, error) {
	now := time.Now()

	// Generate subject identifier
	walletID := session.OpenID4VP.WalletID
	sub := c.generateSubjectIdentifier(walletID, client.ClientID)

	// Get token expiration from config
	idTokenTTL := time.Duration(c.cfg.Verifier.OIDC.IDTokenDuration) * time.Second

	claims := jwt.MapClaims{
		"iss":   c.cfg.Verifier.OIDC.Issuer,
		"sub":   sub,
		"aud":   client.ClientID,
		"exp":   now.Add(idTokenTTL).Unix(),
		"iat":   now.Unix(),
		"nonce": session.OIDCRequest.Nonce,
	}

	// Add verified claims
	maps.Copy(claims, session.VerifiedClaims)

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
