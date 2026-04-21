package apiv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// AuthorizeRequest represents an OIDC authorization request
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required" validate:"required,max=128,printascii"`
	ClientID            string `form:"client_id" binding:"required" validate:"required,max=128,printascii"`
	RedirectURI         string `form:"redirect_uri" binding:"required" validate:"required,max=2048,printascii"`
	Scope               string `form:"scope" binding:"required" validate:"required,max=1024,printascii"`
	State               string `form:"state" validate:"omitempty,max=500,printascii"`
	Nonce               string `form:"nonce" validate:"omitempty,max=256,printascii"`
	CodeChallenge       string `form:"code_challenge" validate:"omitempty,max=128,printascii"`
	CodeChallengeMethod string `form:"code_challenge_method" validate:"omitempty,max=128,printascii"`
	ResponseMode        string `form:"response_mode" validate:"omitempty,max=128,printascii"`
	Display             string `form:"display" validate:"omitempty,max=128,printascii"`
	Prompt              string `form:"prompt" validate:"omitempty,max=128,printascii"`
	MaxAge              int    `form:"max_age"`
	UILocales           string `form:"ui_locales" validate:"omitempty,max=256,printascii"`
	IDTokenHint         string `form:"id_token_hint" validate:"omitempty,max=8192,printascii"`
	LoginHint           string `form:"login_hint" validate:"omitempty,max=256,printascii"`
	ACRValues           string `form:"acr_values" validate:"omitempty,max=512,printascii"`
}

// WalletLink represents a clickable link to a known web wallet
type WalletLink struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	QRCodeImageURL string `json:"qr_code_image_url"` // QR code image URL for cross-device flow
}

// AuthorizeResponse represents the response to an authorization request
type AuthorizeResponse struct {
	SessionID        string       `json:"session_id"`
	QRCodeData       string       `json:"qr_code_data"`
	QRCodeImageURL   string       `json:"qr_code_image_url"`
	DeepLinkURL      string       `json:"deep_link_url"`
	PollURL          string       `json:"poll_url"`
	WalletLinks      []WalletLink `json:"wallet_links,omitempty"`
	PreferredFormats []string     `json:"preferred_formats"`
	UseJAR           bool         `json:"use_jar"`
	ResponseMode     string       `json:"response_mode"`
	Title            string       `json:"title"`
	Subtitle         string       `json:"subtitle"`
	PrimaryColor     string       `json:"primary_color"`
	SecondaryColor   string       `json:"secondary_color"`
	Theme            string       `json:"theme"`
	CustomCSS        string       `json:"custom_css"`
	CSSFile          string       `json:"css_file"`
	LogoURL          string       `json:"logo_url"`
}

// Authorize handles the OIDC authorization request
func (c *Client) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:authorize")
	defer span.End()

	// Validate client (includes static clients from config)
	client, _, err := c.getClientByID(ctx, req.ClientID)
	if err != nil {
		c.log.Error(err, "Failed to get client")
		return nil, ErrServerError
	}
	if client == nil {
		c.log.Info("Client not found", "client_id", req.ClientID)
		return nil, ErrInvalidClient
	}

	// Validate redirect URI
	if !c.matchRedirectURI(client.RedirectURIs, req.RedirectURI) {
		c.log.Info("Invalid redirect URI", "redirect_uri", req.RedirectURI, "allowed_redirect_uris", client.RedirectURIs, "client_id", req.ClientID)
		return nil, ErrInvalidRequest
	}

	// Validate response type
	if !c.containsOIDC(client.ResponseTypes, req.ResponseType) {
		c.log.Info("Unsupported response type", "response_type", req.ResponseType, "allowed_response_types", client.ResponseTypes, "client_id", req.ClientID)
		return nil, ErrInvalidRequest
	}

	// Validate scope - ensure every requested scope is in the client's allow-list
	requestedScopes := strings.Split(req.Scope, " ")
	for _, scope := range requestedScopes {
		if !slices.Contains(client.AllowedScopes, scope) {
			c.log.Info("Invalid scope requested", "scope", scope)
			return nil, ErrInvalidScope
		}
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
		ExpiresAt:           time.Now().Add(time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.CodeDuration) * time.Second).Unix(),
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
	// Use x509_san_dns: prefix so wallets know how to verify the client identity
	host, err := helpers.HostFromURL(c.cfg.Verifier.PublicURL)
	if err != nil {
		c.log.Error(err, "Failed to extract host from PublicURL")
		return nil, ErrServerError
	}
	oidc4vpClientID := fmt.Sprintf("x509_san_dns:%s", host)
	q := url.Values{}
	q.Set("client_id", oidc4vpClientID)
	q.Set("request_uri", requestObjectPath)
	authzReqURL := "openid4vp://cb?" + q.Encode()

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

	// Build wallet links from supported_wallets config
	// Each wallet URL gets the same client_id + request_uri params appended
	for name, walletBaseURL := range c.cfg.Verifier.SupportedWallets {
		walletLink := walletBaseURL + "?" + q.Encode()

		// Build QR code image URL for cross-device flow
		walletQRURL, err := url.JoinPath("/qr", sessionID)
		if err != nil {
			c.log.Error(err, "Failed to construct wallet QR code URL")
			return nil, ErrServerError
		}
		walletQRURL += "?wallet=" + url.QueryEscape(name)

		response.WalletLinks = append(response.WalletLinks, WalletLink{
			Name:           name,
			URL:            walletLink,
			QRCodeImageURL: walletQRURL,
		})
	}

	// Add Digital Credentials API configuration
	response.PreferredFormats = c.cfg.Verifier.DigitalCredentials.PreferredFormats
	response.UseJAR = c.cfg.Verifier.DigitalCredentials.UseJAR
	response.ResponseMode = c.cfg.Verifier.DigitalCredentials.ResponseMode

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
	GrantType    string `form:"grant_type" binding:"required" validate:"required,max=128,printascii"`
	Code         string `form:"code" validate:"omitempty,max=256,printascii"`
	RedirectURI  string `form:"redirect_uri" validate:"omitempty,max=2048,printascii"`
	ClientID     string `form:"client_id" validate:"omitempty,max=128,printascii"`
	ClientSecret string `form:"client_secret" validate:"omitempty,max=256,printascii"`
	CodeVerifier string `form:"code_verifier" validate:"omitempty,max=128,printascii"`
	RefreshToken string `form:"refresh_token" validate:"omitempty,max=256,printascii"`
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

	// Authenticate client (includes static clients from config)
	client, err := c.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		if err == ErrInvalidClient {
			c.log.Info("Client authentication failed")
			return nil, ErrInvalidClient
		}
		c.log.Error(err, "Failed to authenticate client")
		return nil, ErrServerError
	}

	// Verify client ID matches
	if authCtx.ClientID != req.ClientID {
		c.log.Info("Client ID mismatch")
		return nil, ErrInvalidGrant
	}

	// Verify redirect URI matches
	if normalizeRedirectURI(authCtx.RedirectURI) != normalizeRedirectURI(req.RedirectURI) {
		c.log.Info("Redirect URI mismatch")
		return nil, ErrInvalidGrant
	}

	// Validate PKCE if present
	if authCtx.CodeChallenge != "" {
		if err := oauth2.ValidatePKCE(req.CodeVerifier, authCtx.CodeChallenge, authCtx.CodeChallengeMethod); err != nil {
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
	authCtx.AccessTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.AccessTokenDuration) * time.Second).Unix()
	authCtx.IDToken = idToken
	authCtx.RefreshToken = refreshToken
	authCtx.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.RefreshTokenDuration) * time.Second).Unix()
	authCtx.Status = cache.SessionStatusTokenIssued

	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to update session")
		return nil, ErrServerError
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    c.cfg.Verifier.Outbound.OIDCProvider.AccessTokenDuration,
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
	idTokenTTL := time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.IDTokenDuration) * time.Second

	claims := jwt.MapClaims{
		"iss":   c.cfg.Verifier.Outbound.OIDCProvider.Issuer,
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

// DiscoveryMetadata represents OpenID Provider metadata
type DiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"` // RFC 7591
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// GetDiscoveryMetadata returns OpenID Provider configuration
func (c *Client) GetDiscoveryMetadata(ctx context.Context) (*DiscoveryMetadata, error) {
	base := c.cfg.Verifier.PublicURL
	join := func(path string) (string, error) {
		u, err := url.JoinPath(base, path)
		if err != nil {
			return "", fmt.Errorf("failed to construct %s URL: %w", path, err)
		}
		return u, nil
	}

	authorizationEndpoint, err := join("/authorize")
	if err != nil {
		return nil, err
	}
	tokenEndpoint, err := join("/token")
	if err != nil {
		return nil, err
	}
	userInfoEndpoint, err := join("/userinfo")
	if err != nil {
		return nil, err
	}
	jwksURI, err := join("/jwks")
	if err != nil {
		return nil, err
	}
	registrationEndpoint, err := join("/register")
	if err != nil {
		return nil, err
	}

	metadata := &DiscoveryMetadata{
		Issuer:                           c.cfg.Verifier.Outbound.OIDCProvider.Issuer,
		AuthorizationEndpoint:            authorizationEndpoint,
		TokenEndpoint:                    tokenEndpoint,
		UserInfoEndpoint:                 userInfoEndpoint,
		JwksURI:                          jwksURI,
		RegistrationEndpoint:             registrationEndpoint,
		ResponseTypesSupported:           []string{"code", "id_token", "token id_token"},
		SubjectTypesSupported:            []string{"public", "pairwise"},
		IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported: []string{
			"sub", "name", "given_name", "family_name", "email",
			"email_verified", "birthdate", "address",
		},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
	}

	// Add configured credential scopes
	for _, cred := range c.cfg.Verifier.Inbound.OpenID4VP.GetSupportedCredentials() {
		for _, scope := range cred.Scopes {
			metadata.ScopesSupported = append(metadata.ScopesSupported, scope)
		}
	}

	return metadata, nil
}

// GetJWKS returns the JSON Web Key Set
func (c *Client) GetJWKS(ctx context.Context) (*jose.JWKS, error) {
	if c.pkiSigner == nil {
		return nil, fmt.Errorf("signing key not loaded")
	}

	return jose.CreateJWKSFromSigner(c.pkiSigner, "")
}

// GetRequestObjectRequest represents a request to get an OpenID4VP request object
type GetRequestObjectRequest struct {
	SessionID string `json:"-" uri:"session_id" validate:"required,max=128,printascii"`
}

// GetRequestObjectResponse contains the signed JWT request object
type GetRequestObjectResponse struct {
	RequestObject string
}

// GetOIDCRequestObject generates and returns a signed JWT request object for OpenID4VP
func (c *Client) GetOIDCRequestObject(ctx context.Context, req *GetRequestObjectRequest) (*GetRequestObjectResponse, error) {
	// Get session
	session, err := c.cacheService.AuthContext.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Check if session is expired
	if time.Now().Unix() > session.ExpiresAt {
		return nil, ErrSessionExpired
	}

	// Generate nonce for this request
	nonce, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		c.log.Error(err, "Failed to generate nonce")
		return nil, ErrServerError
	}
	session.RequestObjectNonce = nonce
	if err := c.cacheService.AuthContext.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session with nonce")
		return nil, ErrServerError
	}

	// Create and sign request object using DCQL from session
	signedJWT, err := c.CreateRequestObject(ctx, session.SessionID, session.DCQLQuery, nonce)
	if err != nil {
		c.log.Error(err, "Failed to create request object")
		return nil, ErrServerError
	}

	c.log.Debug("Request object signed", "session_id", session.SessionID)

	return &GetRequestObjectResponse{
		RequestObject: signedJWT,
	}, nil
}

// DirectPostRequest represents a direct_post callback from a wallet
type DirectPostRequest struct {
	State                  string `json:"state" form:"state" binding:"required" validate:"required,max=256,printascii"`
	VPToken                string `json:"vp_token" form:"vp_token" validate:"omitempty"`                               // For standard direct_post (JWT, can be very large)
	PresentationSubmission string `json:"presentation_submission" form:"presentation_submission" validate:"omitempty"` // For standard direct_post (JSON, can be large)
	Response               string `json:"response" form:"response" validate:"omitempty"`                               // For DC API encrypted JWT response (can be very large)
}

// DirectPostResponse contains the response to a direct_post request
type DirectPostResponse struct {
	RedirectURI string
}

// ProcessDirectPost processes a direct_post response from a wallet
func (c *Client) ProcessDirectPost(ctx context.Context, req *DirectPostRequest) (*DirectPostResponse, error) {
	// Get session by state
	session, err := c.cacheService.AuthContext.GetByID(ctx, req.State)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	var vpToken string
	var presentationSubmission any

	// Check if this is a DC API response (encrypted JWT) or standard form-encoded
	if req.Response != "" {
		// DC API response - decrypt and extract vp_token
		c.log.Debug("Processing DC API encrypted response", "state", req.State)

		// TODO: Implement JWT decryption using OIDC keys
		// For now, treat response as the vp_token
		vpToken = req.Response

		c.log.Info("DC API response decryption not yet implemented, treating response as vp_token")
	} else if req.VPToken != "" {
		// Standard direct_post with form-encoded parameters
		vpToken = req.VPToken

		// Parse presentation submission if provided
		if req.PresentationSubmission != "" {
			if err := json.Unmarshal([]byte(req.PresentationSubmission), &presentationSubmission); err != nil {
				c.log.Error(err, "Failed to parse presentation submission")
				// Continue anyway - presentation submission is optional
			}
		}
	} else {
		c.log.Error(nil, "Neither vp_token nor response parameter provided")
		return nil, ErrInvalidRequest
	}

	// Validate and parse VP token
	c.log.Debug("Processing VP token", "state", req.State, "vp_token_length", len(vpToken))

	// Extract and map claims from VP token
	oidcClaims, err := c.extractAndMapClaims(ctx, vpToken, strings.Join(session.Scopes, " "))
	if err != nil {
		c.log.Error(err, "Failed to extract and map claims from VP token")
		return nil, ErrInvalidVP
	}

	c.log.Debug("Mapped OIDC claims from VP", "claims", oidcClaims)

	// Update session with VP data
	session.VPToken = vpToken
	session.PresentationSubmission = presentationSubmission
	session.VerifiedClaims = oidcClaims

	// Extract wallet ID from claims
	if sub, ok := oidcClaims["sub"].(string); ok {
		session.WalletID = sub
	}

	// Check if user requested credential display
	if session.ShowCredentialDetails {
		session.Status = cache.SessionStatusAwaitingPresentation

		if err := c.cacheService.AuthContext.Update(ctx, session); err != nil {
			c.log.Error(err, "Failed to update session")
			return nil, ErrServerError
		}

		c.log.Info("Redirecting to credential display page", "session_id", session.SessionID)

		displayURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "verification", "display", session.SessionID)
		if err != nil {
			c.log.Error(err, "Failed to construct display URI")
			return nil, ErrServerError
		}

		return &DirectPostResponse{
			RedirectURI: displayURI,
		}, nil
	}

	// Otherwise, issue authorization code immediately
	session.Status = cache.SessionStatusCodeIssued

	code, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate authorization code")
		return nil, ErrServerError
	}
	codeExpiry := time.Now().Add(time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.CodeDuration) * time.Second)

	session.Code = code
	session.CodeExpiresAt = codeExpiry.Unix()

	if err := c.cacheService.AuthContext.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session")
		return nil, ErrServerError
	}

	c.log.Info("VP processed successfully", "session_id", session.SessionID, "claims_count", len(oidcClaims))

	// Return redirect URI if present
	redirectURI := ""
	if session.RedirectURI != "" {
		u, err := url.Parse(session.RedirectURI)
		if err != nil {
			c.log.Error(err, "Failed to parse redirect URI")
			return nil, ErrServerError
		}
		q := u.Query()
		q.Set("code", code)
		q.Set("state", session.State)
		u.RawQuery = q.Encode()
		redirectURI = u.String()
	}

	return &DirectPostResponse{
		RedirectURI: redirectURI,
	}, nil
}

// CallbackRequest represents a callback request
type CallbackRequest struct {
	State string `form:"state" binding:"required" validate:"required,max=128,printascii"`
	Code  string `form:"code" validate:"omitempty,max=128,printascii"`
	Error string `form:"error" validate:"omitempty,max=1000,printascii"`
}

// CallbackResponse contains the redirect URI
type CallbackResponse struct {
	RedirectURI string
}

// ProcessCallback processes a callback request
func (c *Client) ProcessCallback(ctx context.Context, req *CallbackRequest) (*CallbackResponse, error) {
	// Get session
	session, err := c.cacheService.AuthContext.GetByID(ctx, req.State)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Handle error response
	if req.Error != "" {
		session.Status = cache.SessionStatusError
		if err := c.cacheService.AuthContext.Update(ctx, session); err != nil {
			c.log.Error(err, "Failed to update session")
			return nil, ErrServerError
		}

		u, err := url.Parse(session.RedirectURI)
		if err != nil {
			c.log.Error(err, "Failed to parse redirect URI")
			return nil, ErrServerError
		}
		q := u.Query()
		q.Set("error", req.Error)
		q.Set("state", session.State)
		u.RawQuery = q.Encode()

		resp := &CallbackResponse{
			RedirectURI: u.String(),
		}
		return resp, nil
	}

	// Build redirect URI with code
	u, err := url.Parse(session.RedirectURI)
	if err != nil {
		c.log.Error(err, "Failed to parse redirect URI")
		return nil, ErrServerError
	}
	q := u.Query()
	q.Set("code", req.Code)
	q.Set("state", session.State)
	u.RawQuery = q.Encode()

	resp := &CallbackResponse{
		RedirectURI: u.String(),
	}

	return resp, nil
}

// GetQRCodeRequest represents a request for a QR code image
type GetQRCodeRequest struct {
	SessionID  string `json:"-" uri:"session_id" validate:"required,max=128,printascii"`
	WalletName string `json:"-" form:"wallet" validate:"omitempty,max=128,printascii"` // Optional: generate QR for a specific web wallet
}

// GetQRCodeResponse contains the QR code image data
type GetQRCodeResponse struct {
	ImageData []byte
}

// GetQRCode generates a QR code image for a session
func (c *Client) GetQRCode(ctx context.Context, req *GetQRCodeRequest) (*GetQRCodeResponse, error) {
	// Get session
	session, err := c.cacheService.AuthContext.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	var qrData string

	if req.WalletName != "" {
		// Cross-device web wallet flow: generate QR for a specific web wallet URL
		walletBaseURL, ok := c.cfg.Verifier.SupportedWallets[req.WalletName]
		if !ok {
			return nil, ErrInvalidRequest
		}

		// Build the web wallet URL with the same authorization params
		requestObjectPath, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/request-object", req.SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to construct request object path: %w", err)
		}

		host, err := helpers.HostFromURL(c.cfg.Verifier.PublicURL)
		if err != nil {
			return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
		}

		q := url.Values{}
		q.Set("client_id", fmt.Sprintf("x509_san_dns:%s", host))
		q.Set("request_uri", requestObjectPath)
		qrData = walletBaseURL + "?" + q.Encode()
	} else {
		// Standard flow: generate QR for openid4vp:// URI (native wallet)
		host, err := helpers.HostFromURL(c.cfg.Verifier.PublicURL)
		if err != nil {
			return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
		}

		requestObject := &openid4vp.RequestObject{
			ClientID: fmt.Sprintf("x509_san_dns:%s", host),
		}
		qrData, err = requestObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.PublicURL, req.SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to create authorization request URI: %w", err)
		}
	}

	// Generate QR code
	qr, err := qrcode.New(qrData, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Encode to PNG
	var buf bytes.Buffer
	img := qr.Image(256)
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode QR code: %w", err)
	}

	return &GetQRCodeResponse{
		ImageData: buf.Bytes(),
	}, nil
}

// PollSessionRequest represents a polling request for session status
type PollSessionRequest struct {
	SessionID string `json:"-" uri:"session_id" validate:"required,max=128,printascii"`
}

// PollSessionResponse contains the session status
type PollSessionResponse struct {
	Status      string `json:"status"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// PollSession returns the current status of a session
func (c *Client) PollSession(ctx context.Context, req *PollSessionRequest) (*PollSessionResponse, error) {
	// Get session
	session, err := c.cacheService.AuthContext.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	response := &PollSessionResponse{
		Status: string(session.Status),
	}

	// If code is issued, provide redirect URI
	if session.Status == cache.SessionStatusCodeIssued {
		u, err := url.Parse(session.RedirectURI)
		if err != nil {
			c.log.Error(err, "Failed to parse redirect URI")
			return nil, ErrServerError
		}
		q := u.Query()
		q.Set("code", session.Code)
		q.Set("state", session.State)
		u.RawQuery = q.Encode()
		response.RedirectURI = u.String()
	}

	return response, nil
}

// UserInfoRequest represents a UserInfo endpoint request
type UserInfoRequest struct {
	Authorization string `json:"-" header:"Authorization" validate:"required,max=256,printascii"`
	AccessToken   string `json:"-"` // Parsed from Authorization header
}

// UserInfoResponse contains user claims
type UserInfoResponse map[string]any

// GetUserInfo returns user claims based on access token
func (c *Client) GetUserInfo(ctx context.Context, req *UserInfoRequest) (UserInfoResponse, error) {
	// Get session by access token
	session, err := c.cacheService.AuthContext.GetByAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if session == nil {
		return nil, ErrInvalidGrant
	}

	// Check if access token is expired
	if time.Now().Unix() > session.AccessTokenExpiresAt {
		return nil, ErrInvalidGrant
	}

	// Generate subject identifier
	walletID := ""
	if val, ok := session.VerifiedClaims["sub"]; ok {
		if str, ok := val.(string); ok {
			walletID = str
		}
	}

	subject := c.generateSubjectIdentifier(walletID, session.ClientID)

	// Return verified claims
	response := UserInfoResponse{
		"sub": subject,
	}

	// Add verified claims from VP
	maps.Copy(response, session.VerifiedClaims)

	return response, nil
}

// normalizeRedirectURI normalizes a redirect URI for comparison.
// Decodes percent-encoding so that e.g. "Test%20Realm" and "Test Realm"
// compare as equal. Uses PathUnescape (not QueryUnescape) so that "+" is
// left intact — it is a valid path character.
func normalizeRedirectURI(uri string) string {
	decoded, err := url.PathUnescape(uri)
	if err != nil {
		return uri
	}
	return decoded
}

// matchRedirectURI checks whether reqURI matches any of the registered URIs
// using normalized comparison per RFC 3986 Section 6.
func (c *Client) matchRedirectURI(registered []string, reqURI string) bool {
	normReq := normalizeRedirectURI(reqURI)
	for _, r := range registered {
		if normalizeRedirectURI(r) == normReq {
			return true
		}
	}
	return false
}
