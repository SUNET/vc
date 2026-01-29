package apiv1

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"math/big"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/crypto"

	"github.com/skip2/go-qrcode"
)

// Request and Response types for API handlers

// GetRequestObjectRequest represents a request to get an OpenID4VP request object
type GetRequestObjectRequest struct {
	SessionID string
}

// GetRequestObjectResponse contains the signed JWT request object
type GetRequestObjectResponse struct {
	RequestObject string
}

// DirectPostRequest represents a direct_post callback from a wallet
type DirectPostRequest struct {
	State                  string `form:"state" binding:"required"`
	VPToken                string `form:"vp_token"`                // For standard direct_post
	PresentationSubmission string `form:"presentation_submission"` // For standard direct_post
	Response               string `form:"response"`                // For DC API encrypted JWT response
}

// DirectPostResponse contains the response to a direct_post request
type DirectPostResponse struct {
	RedirectURI string
}

// CallbackRequest represents a callback request
type CallbackRequest struct {
	State string `form:"state" binding:"required"`
	Code  string `form:"code"`
	Error string `form:"error"`
}

// CallbackResponse contains the redirect URI
type CallbackResponse struct {
	RedirectURI string
}

// GetQRCodeRequest represents a request for a QR code image
type GetQRCodeRequest struct {
	SessionID string
}

// GetQRCodeResponse contains the QR code image data
type GetQRCodeResponse struct {
	ImageData []byte
}

// PollSessionRequest represents a polling request for session status
type PollSessionRequest struct {
	SessionID string
}

// PollSessionResponse contains the session status
type PollSessionResponse struct {
	Status      string
	RedirectURI string
}

// UserInfoRequest represents a UserInfo endpoint request
type UserInfoRequest struct {
	AccessToken string
}

// UserInfoResponse contains user claims
type UserInfoResponse map[string]any

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

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// GetDiscoveryMetadata returns OpenID Provider configuration
func (c *Client) GetDiscoveryMetadata(ctx context.Context) (*DiscoveryMetadata, error) {
	baseURL := c.cfg.VerifierProxy.ExternalURL

	metadata := &DiscoveryMetadata{
		Issuer:                           c.cfg.VerifierProxy.OIDC.Issuer,
		AuthorizationEndpoint:            baseURL + "/authorize",
		TokenEndpoint:                    baseURL + "/token",
		UserInfoEndpoint:                 baseURL + "/userinfo",
		JwksURI:                          baseURL + "/jwks",
		RegistrationEndpoint:             baseURL + "/register",
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
	for _, cred := range c.cfg.VerifierProxy.OpenID4VP.SupportedCredentials {
		for _, scope := range cred.Scopes {
			metadata.ScopesSupported = append(metadata.ScopesSupported, scope)
		}
	}

	return metadata, nil
}

// GetJWKS returns the JSON Web Key Set
func (c *Client) GetJWKS(ctx context.Context) (*JWKS, error) {
	if c.oidcSigningKey == nil {
		return nil, fmt.Errorf("signing key not loaded")
	}

	switch key := c.oidcSigningKey.(type) {
	case *rsa.PrivateKey:
		publicKey := &key.PublicKey
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: "default",
			Alg: c.oidcSigningAlg,
			N:   n,
			E:   e,
		}
		return &JWKS{Keys: []JWK{jwk}}, nil

	case *ecdsa.PrivateKey:
		publicKey := &key.PublicKey
		x := base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes())

		crv := ""
		switch publicKey.Curve.Params().BitSize {
		case 256:
			crv = "P-256"
		case 384:
			crv = "P-384"
		case 521:
			crv = "P-521"
		}

		jwk := JWK{
			Kty: "EC",
			Use: "sig",
			Kid: "default",
			Alg: c.oidcSigningAlg,
			Crv: crv,
			X:   x,
			Y:   y,
		}
		return &JWKS{Keys: []JWK{jwk}}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", c.oidcSigningKey)
	}
}

// GetOIDCRequestObject generates and returns a signed JWT request object for OpenID4VP
func (c *Client) GetOIDCRequestObject(ctx context.Context, req *GetRequestObjectRequest) (*GetRequestObjectResponse, error) {
	// Get session
	session, err := c.db.Sessions.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	// Generate nonce for this request
	nonce, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		c.log.Error(err, "Failed to generate nonce")
		return nil, ErrServerError
	}
	session.OpenID4VP.RequestObjectNonce = nonce
	if err := c.db.Sessions.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session with nonce")
		return nil, ErrServerError
	}

	// Create and sign request object using DCQL from session
	signedJWT, err := c.CreateRequestObject(ctx, session.ID, session.OpenID4VP.DCQL, nonce)
	if err != nil {
		c.log.Error(err, "Failed to create request object")
		return nil, ErrServerError
	}

	c.log.Debug("Request object signed", "session_id", session.ID)

	return &GetRequestObjectResponse{
		RequestObject: signedJWT,
	}, nil
}

// ProcessDirectPost processes a direct_post response from a wallet
func (c *Client) ProcessDirectPost(ctx context.Context, req *DirectPostRequest) (*DirectPostResponse, error) {
	// Get session by state
	session, err := c.db.Sessions.GetByID(ctx, req.State)
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
	oidcClaims, err := c.extractAndMapClaims(ctx, vpToken, session.OIDCRequest.Scope)
	if err != nil {
		c.log.Error(err, "Failed to extract and map claims from VP token")
		return nil, ErrInvalidVP
	}

	c.log.Debug("Mapped OIDC claims from VP", "claims", oidcClaims)

	// Update session with VP data
	session.OpenID4VP.VPToken = vpToken
	session.OpenID4VP.PresentationSubmission = presentationSubmission
	session.VerifiedClaims = oidcClaims

	// Extract wallet ID from claims
	if sub, ok := oidcClaims["sub"].(string); ok {
		session.OpenID4VP.WalletID = sub
	}

	// Check if user requested credential display
	if session.OIDCRequest.ShowCredentialDetails {
		session.Status = db.SessionStatusAwaitingPresentation

		if err := c.db.Sessions.Update(ctx, session); err != nil {
			c.log.Error(err, "Failed to update session")
			return nil, ErrServerError
		}

		c.log.Info("Redirecting to credential display page", "session_id", session.ID)

		return &DirectPostResponse{
			RedirectURI: fmt.Sprintf("%s/verification/display/%s", c.cfg.VerifierProxy.ExternalURL, session.ID),
		}, nil
	}

	// Otherwise, issue authorization code immediately
	session.Status = db.SessionStatusCodeIssued

	code := c.generateAuthorizationCode()
	codeExpiry := time.Now().Add(time.Duration(c.cfg.VerifierProxy.OIDC.CodeDuration) * time.Second)

	session.Tokens.AuthorizationCode = code
	session.Tokens.CodeExpiresAt = codeExpiry

	if err := c.db.Sessions.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session")
		return nil, ErrServerError
	}

	c.log.Info("VP processed successfully", "session_id", session.ID, "claims_count", len(oidcClaims))

	// Return redirect URI if present
	redirectURI := ""
	if session.OIDCRequest.RedirectURI != "" {
		redirectURI = fmt.Sprintf("%s?code=%s&state=%s",
			session.OIDCRequest.RedirectURI,
			code,
			session.OIDCRequest.State,
		)
	}

	return &DirectPostResponse{
		RedirectURI: redirectURI,
	}, nil
}

// ProcessCallback processes a callback request
func (c *Client) ProcessCallback(ctx context.Context, req *CallbackRequest) (*CallbackResponse, error) {
	// Get session
	session, err := c.db.Sessions.GetByID(ctx, req.State)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Handle error response
	if req.Error != "" {
		session.Status = db.SessionStatusError
		_ = c.db.Sessions.Update(ctx, session)

		redirectURI := fmt.Sprintf("%s?error=%s&state=%s",
			session.OIDCRequest.RedirectURI,
			req.Error,
			session.OIDCRequest.State,
		)

		return &CallbackResponse{
			RedirectURI: redirectURI,
		}, nil
	}

	// Build redirect URI with code
	redirectURI := fmt.Sprintf("%s?code=%s&state=%s",
		session.OIDCRequest.RedirectURI,
		req.Code,
		session.OIDCRequest.State,
	)

	return &CallbackResponse{
		RedirectURI: redirectURI,
	}, nil
}

// GetQRCode generates a QR code image for a session
func (c *Client) GetQRCode(ctx context.Context, req *GetQRCodeRequest) (*GetQRCodeResponse, error) {
	// Get session
	session, err := c.db.Sessions.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Generate authorization request URI
	authReqURI, err := c.createAuthorizationRequestURI(req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization request URI: %w", err)
	}

	// Generate QR code
	qr, err := qrcode.New(authReqURI, qrcode.Medium)
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

// PollSession returns the current status of a session
func (c *Client) PollSession(ctx context.Context, req *PollSessionRequest) (*PollSessionResponse, error) {
	// Get session
	session, err := c.db.Sessions.GetByID(ctx, req.SessionID)
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
	if session.Status == db.SessionStatusCodeIssued {
		response.RedirectURI = fmt.Sprintf("%s?code=%s&state=%s",
			session.OIDCRequest.RedirectURI,
			session.Tokens.AuthorizationCode,
			session.OIDCRequest.State,
		)
	}

	return response, nil
}

// GetUserInfo returns user claims based on access token
func (c *Client) GetUserInfo(ctx context.Context, req *UserInfoRequest) (UserInfoResponse, error) {
	// Get session by access token
	session, err := c.db.Sessions.GetByAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if session == nil {
		return nil, ErrInvalidGrant
	}

	// Check if access token is expired
	if session.Tokens.AccessTokenExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidGrant
	}

	// Generate subject identifier
	walletID := ""
	if val, ok := session.VerifiedClaims["sub"]; ok {
		if str, ok := val.(string); ok {
			walletID = str
		}
	}

	subject := c.generateSubjectIdentifier(walletID, session.OIDCRequest.ClientID)

	// Return verified claims
	response := UserInfoResponse{
		"sub": subject,
	}

	// Add verified claims from VP
	for k, v := range session.VerifiedClaims {
		response[k] = v
	}

	return response, nil
}

// createAuthorizationRequestURI creates the OpenID4VP authorization request URI
func (c *Client) createAuthorizationRequestURI(sessionID string) (string, error) {
	baseURL := c.cfg.VerifierProxy.ExternalURL
	requestURI := fmt.Sprintf("%s/verification/request-object/%s", baseURL, sessionID)

	// Build authorization request URI per OpenID4VP spec
	authReqURI := fmt.Sprintf("openid4vp://?client_id=%s&request_uri=%s",
		c.cfg.VerifierProxy.OIDC.Issuer,
		requestURI,
	)

	return authReqURI, nil
}
