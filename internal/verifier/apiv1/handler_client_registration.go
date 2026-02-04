package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"vc/internal/verifier/apiv1/utils"
	"vc/internal/verifier/db"

	"golang.org/x/crypto/bcrypt"
)

// ClientRegistrationRequest represents RFC 7591 client registration request
type ClientRegistrationRequest struct {
	// REQUIRED or OPTIONAL OAuth 2.0 parameters
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // Default: "client_secret_basic"
	GrantTypes              []string `json:"grant_types,omitempty"`                // Default: ["authorization_code"]
	ResponseTypes           []string `json:"response_types,omitempty"`             // Default: ["code"]
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JWKSUri                 string   `json:"jwks_uri,omitempty"`
	JWKS                    any      `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`

	// OpenID Connect specific
	ApplicationType         string   `json:"application_type,omitempty"` // "web" or "native"
	SectorIdentifierURI     string   `json:"sector_identifier_uri,omitempty"`
	SubjectType             string   `json:"subject_type,omitempty"` // "public" or "pairwise"
	IDTokenSignedRespAlg    string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedRespAlg string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedRespEnc string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedRespAlg   string   `json:"userinfo_signed_response_alg,omitempty"`
	RequestObjectSigningAlg string   `json:"request_object_signing_alg,omitempty"`
	DefaultMaxAge           int      `json:"default_max_age,omitempty"`
	RequireAuthTime         bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues        []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI        string   `json:"initiate_login_uri,omitempty"`
	RequestURIs             []string `json:"request_uris,omitempty"`

	// PKCE (RFC 7636)
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"` // "S256" or "plain"
}

// ClientRegistrationResponse represents RFC 7591 client registration response
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"` // 0 = never expires, REQUIRED per RFC 7591
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JWKSUri                 string   `json:"jwks_uri,omitempty"`
	JWKS                    any      `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`

	// OpenID Connect specific
	ApplicationType      string   `json:"application_type,omitempty"`
	SectorIdentifierURI  string   `json:"sector_identifier_uri,omitempty"`
	SubjectType          string   `json:"subject_type,omitempty"`
	IDTokenSignedRespAlg string   `json:"id_token_signed_response_alg,omitempty"`
	DefaultMaxAge        int      `json:"default_max_age,omitempty"`
	RequireAuthTime      bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues     []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI     string   `json:"initiate_login_uri,omitempty"`
	RequestURIs          []string `json:"request_uris,omitempty"`

	// PKCE
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// ClientInformationResponse represents RFC 7592 client information response (GET)
type ClientInformationResponse struct {
	ClientRegistrationResponse
}

// RegisterClient handles dynamic client registration (RFC 7591)
func (c *Client) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:register_client")
	defer span.End()

	// Validate request
	if err := c.validateRegistrationRequest(req); err != nil {
		return nil, err
	}

	// Apply defaults
	c.applyRegistrationDefaults(req)

	// Generate client credentials
	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Hash client secret for storage
	secretHash, err := hashClientSecret(clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	// Generate registration access token
	registrationAccessToken, err := generateRegistrationAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate registration access token: %w", err)
	}

	// Hash registration access token for storage
	ratHash, err := hashRegistrationAccessToken(registrationAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash registration access token: %w", err)
	}

	// Convert scope string to slice
	allowedScopes := []string{}
	if req.Scope != "" {
		allowedScopes = strings.Split(req.Scope, " ")
	}

	// Determine if PKCE is required
	requirePKCE := req.CodeChallengeMethod != ""
	requireCodeChallenge := requirePKCE

	// Create client in database
	now := time.Now()
	client := &db.Client{
		ClientID:                    clientID,
		ClientSecretHash:            secretHash,
		RedirectURIs:                req.RedirectURIs,
		GrantTypes:                  req.GrantTypes,
		ResponseTypes:               req.ResponseTypes,
		TokenEndpointAuthMethod:     req.TokenEndpointAuthMethod,
		AllowedScopes:               allowedScopes,
		SubjectType:                 req.SubjectType,
		JWKSUri:                     req.JWKSUri,
		JWKS:                        req.JWKS,
		RequirePKCE:                 requirePKCE,
		RequireCodeChallenge:        requireCodeChallenge,
		ClientName:                  req.ClientName,
		ClientURI:                   req.ClientURI,
		LogoURI:                     req.LogoURI,
		Contacts:                    req.Contacts,
		TosURI:                      req.TosURI,
		PolicyURI:                   req.PolicyURI,
		SoftwareID:                  req.SoftwareID,
		SoftwareVersion:             req.SoftwareVersion,
		ApplicationType:             req.ApplicationType,
		SectorIdentifierURI:         req.SectorIdentifierURI,
		IDTokenSignedResponseAlg:    req.IDTokenSignedRespAlg,
		DefaultMaxAge:               req.DefaultMaxAge,
		RequireAuthTime:             req.RequireAuthTime,
		DefaultACRValues:            req.DefaultACRValues,
		InitiateLoginURI:            req.InitiateLoginURI,
		RequestURIs:                 req.RequestURIs,
		CodeChallengeMethod:         req.CodeChallengeMethod,
		RegistrationAccessTokenHash: ratHash,
		ClientIDIssuedAt:            now.Unix(),
		ClientSecretExpiresAt:       0, // Never expires (0 means no expiration per RFC 7591)
	}

	err = c.db.Clients.Create(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Build response
	registrationClientURI := fmt.Sprintf("%s/register/%s", c.cfg.Verifier.PublicURL, clientID)

	response := &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        now.Unix(),
		ClientSecretExpiresAt:   0, // Never expires
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TosURI:                  req.TosURI,
		PolicyURI:               req.PolicyURI,
		JWKSUri:                 req.JWKSUri,
		JWKS:                    req.JWKS,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		RegistrationAccessToken: registrationAccessToken,
		RegistrationClientURI:   registrationClientURI,
		ApplicationType:         req.ApplicationType,
		SectorIdentifierURI:     req.SectorIdentifierURI,
		SubjectType:             req.SubjectType,
		IDTokenSignedRespAlg:    req.IDTokenSignedRespAlg,
		DefaultMaxAge:           req.DefaultMaxAge,
		RequireAuthTime:         req.RequireAuthTime,
		DefaultACRValues:        req.DefaultACRValues,
		InitiateLoginURI:        req.InitiateLoginURI,
		RequestURIs:             req.RequestURIs,
		CodeChallengeMethod:     req.CodeChallengeMethod,
	}

	return response, nil
}

// GetClientInformation retrieves client configuration (RFC 7592)
func (c *Client) GetClientInformation(ctx context.Context, clientID string, registrationAccessToken string) (*ClientInformationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_client_information")
	defer span.End()

	// Get client from database
	client, err := c.db.Clients.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	// Verify registration access token
	if err := verifyRegistrationAccessToken(registrationAccessToken, client.RegistrationAccessTokenHash); err != nil {
		return nil, ErrInvalidToken
	}

	// Build response
	scope := strings.Join(client.AllowedScopes, " ")

	response := &ClientInformationResponse{
		ClientRegistrationResponse: ClientRegistrationResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        client.ClientIDIssuedAt,
			ClientSecretExpiresAt:   client.ClientSecretExpiresAt,
			RedirectURIs:            client.RedirectURIs,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           client.ResponseTypes,
			ClientName:              client.ClientName,
			ClientURI:               client.ClientURI,
			LogoURI:                 client.LogoURI,
			Scope:                   scope,
			Contacts:                client.Contacts,
			TosURI:                  client.TosURI,
			PolicyURI:               client.PolicyURI,
			JWKSUri:                 client.JWKSUri,
			JWKS:                    client.JWKS,
			SoftwareID:              client.SoftwareID,
			SoftwareVersion:         client.SoftwareVersion,
			RegistrationClientURI:   fmt.Sprintf("%s/register/%s", c.cfg.Verifier.PublicURL, clientID),
			ApplicationType:         client.ApplicationType,
			SectorIdentifierURI:     client.SectorIdentifierURI,
			SubjectType:             client.SubjectType,
			IDTokenSignedRespAlg:    client.IDTokenSignedResponseAlg,
			DefaultMaxAge:           client.DefaultMaxAge,
			RequireAuthTime:         client.RequireAuthTime,
			DefaultACRValues:        client.DefaultACRValues,
			InitiateLoginURI:        client.InitiateLoginURI,
			RequestURIs:             client.RequestURIs,
			CodeChallengeMethod:     client.CodeChallengeMethod,
		},
	}

	return response, nil
}

// DeleteClient deletes a client registration (RFC 7592)
func (c *Client) DeleteClient(ctx context.Context, clientID string, registrationAccessToken string) error {
	ctx, span := c.tracer.Start(ctx, "apiv1:delete_client")
	defer span.End()

	// Get existing client
	client, err := c.db.Clients.GetByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if client == nil {
		return ErrInvalidClient
	}

	// Verify registration access token
	if err := verifyRegistrationAccessToken(registrationAccessToken, client.RegistrationAccessTokenHash); err != nil {
		return ErrInvalidToken
	}

	// Delete client
	return c.db.Clients.Delete(ctx, clientID)
}

// UpdateClient updates client configuration (RFC 7592)
func (c *Client) UpdateClient(ctx context.Context, clientID string, registrationAccessToken string, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:update_client")
	defer span.End()

	// Get existing client
	client, err := c.db.Clients.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	// Verify registration access token
	if err := verifyRegistrationAccessToken(registrationAccessToken, client.RegistrationAccessTokenHash); err != nil {
		return nil, ErrInvalidToken
	}

	// Validate update request
	if err := c.validateRegistrationRequest(req); err != nil {
		return nil, err
	}

	// Apply defaults
	c.applyRegistrationDefaults(req)

	// Update client fields
	if req.RedirectURIs != nil {
		client.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		client.GrantTypes = req.GrantTypes
	}
	if req.ResponseTypes != nil {
		client.ResponseTypes = req.ResponseTypes
	}
	if req.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	if req.Scope != "" {
		client.AllowedScopes = strings.Split(req.Scope, " ")
	}
	if req.SubjectType != "" {
		client.SubjectType = req.SubjectType
	}
	if req.JWKSUri != "" {
		client.JWKSUri = req.JWKSUri
	}
	if req.JWKS != nil {
		client.JWKS = req.JWKS
	}
	if req.ClientName != "" {
		client.ClientName = req.ClientName
	}
	if req.ClientURI != "" {
		client.ClientURI = req.ClientURI
	}
	if req.LogoURI != "" {
		client.LogoURI = req.LogoURI
	}
	if req.Contacts != nil {
		client.Contacts = req.Contacts
	}
	if req.TosURI != "" {
		client.TosURI = req.TosURI
	}
	if req.PolicyURI != "" {
		client.PolicyURI = req.PolicyURI
	}
	if req.CodeChallengeMethod != "" {
		client.CodeChallengeMethod = req.CodeChallengeMethod
		client.RequirePKCE = true
		client.RequireCodeChallenge = true
	}

	// Update in database
	err = c.db.Clients.Update(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	// Build response (same as GET)
	scope := strings.Join(client.AllowedScopes, " ")

	response := &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        client.ClientIDIssuedAt,
		ClientSecretExpiresAt:   client.ClientSecretExpiresAt,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		Scope:                   scope,
		Contacts:                client.Contacts,
		TosURI:                  client.TosURI,
		PolicyURI:               client.PolicyURI,
		JWKSUri:                 client.JWKSUri,
		JWKS:                    client.JWKS,
		SoftwareID:              client.SoftwareID,
		SoftwareVersion:         client.SoftwareVersion,
	RegistrationClientURI:   fmt.Sprintf("%s/register/%s", c.cfg.Verifier.PublicURL, clientID),
		ApplicationType:         client.ApplicationType,
		SectorIdentifierURI:     client.SectorIdentifierURI,
		SubjectType:             client.SubjectType,
		IDTokenSignedRespAlg:    client.IDTokenSignedResponseAlg,
		DefaultMaxAge:           client.DefaultMaxAge,
		RequireAuthTime:         client.RequireAuthTime,
		DefaultACRValues:        client.DefaultACRValues,
		InitiateLoginURI:        client.InitiateLoginURI,
		RequestURIs:             client.RequestURIs,
		CodeChallengeMethod:     client.CodeChallengeMethod,
	}

	return response, nil
}

// validateRegistrationRequest validates RFC 7591 client registration request
func (c *Client) validateRegistrationRequest(req *ClientRegistrationRequest) error {
	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("%w: redirect_uris is required", ErrInvalidRequest)
	}

	// Basic validation - each URI should be parseable
	for _, uri := range req.RedirectURIs {
		if err := utils.ValidateRedirectURIFormat(uri); err != nil {
			return fmt.Errorf("%w: invalid redirect_uri: %s - %v", ErrInvalidRequest, uri, err)
		}
	}

	// Validate token endpoint auth method
	if req.TokenEndpointAuthMethod != "" {
		validMethods := map[string]bool{
			"client_secret_basic": true,
			"client_secret_post":  true,
			"none":                true,
		}
		if !validMethods[req.TokenEndpointAuthMethod] {
			return fmt.Errorf("%w: unsupported token_endpoint_auth_method", ErrInvalidRequest)
		}
	}

	// Validate grant types
	if len(req.GrantTypes) > 0 {
		validGrantTypes := map[string]bool{
			"authorization_code": true,
			"refresh_token":      true,
		}
		for _, gt := range req.GrantTypes {
			if !validGrantTypes[gt] {
				return fmt.Errorf("%w: unsupported grant_type: %s", ErrInvalidRequest, gt)
			}
		}
	}

	// Validate response types
	if len(req.ResponseTypes) > 0 {
		validResponseTypes := map[string]bool{
			"code": true,
		}
		for _, rt := range req.ResponseTypes {
			if !validResponseTypes[rt] {
				return fmt.Errorf("%w: unsupported response_type: %s", ErrInvalidRequest, rt)
			}
		}
	}

	// Validate subject type
	if req.SubjectType != "" {
		if req.SubjectType != "public" && req.SubjectType != "pairwise" {
			return fmt.Errorf("%w: subject_type must be 'public' or 'pairwise'", ErrInvalidRequest)
		}
	}

	// Validate PKCE code challenge method
	if req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return fmt.Errorf("%w: code_challenge_method must be 'S256' or 'plain'", ErrInvalidRequest)
		}
	}

	// Validate JWKS (either jwks_uri or jwks, not both)
	if req.JWKSUri != "" && req.JWKS != nil {
		return fmt.Errorf("%w: cannot specify both jwks_uri and jwks", ErrInvalidRequest)
	}

	// Validate logo_uri (RFC 7591 Section 2)
	if req.LogoURI != "" {
		if err := utils.ValidateHTTPSURI(req.LogoURI, "logo_uri"); err != nil {
			return fmt.Errorf("%w: invalid logo_uri: %v", ErrInvalidRequest, err)
		}
	}

	// Validate client_uri
	if req.ClientURI != "" {
		if err := utils.ValidateHTTPSURI(req.ClientURI, "client_uri"); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	}

	// Validate policy_uri
	if req.PolicyURI != "" {
		if err := utils.ValidateHTTPSURI(req.PolicyURI, "policy_uri"); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	}

	// Validate tos_uri
	if req.TosURI != "" {
		if err := utils.ValidateHTTPSURI(req.TosURI, "tos_uri"); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	}

	return nil
}

// applyRegistrationDefaults applies default values per RFC 7591
func (c *Client) applyRegistrationDefaults(req *ClientRegistrationRequest) {
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}

	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	if req.SubjectType == "" {
		req.SubjectType = "public"
	}

	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}

	if req.IDTokenSignedRespAlg == "" {
		req.IDTokenSignedRespAlg = "RS256"
	}

	// Default scope if not specified
	if req.Scope == "" {
		req.Scope = "openid"
	}
}

// Helper functions

func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func generateRegistrationAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashRegistrationAccessToken(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]), nil
}

func verifyRegistrationAccessToken(token, hash string) error {
	computedHash := sha256.Sum256([]byte(token))
	computedHashHex := hex.EncodeToString(computedHash[:])

	if computedHashHex != hash {
		return ErrInvalidToken
	}
	return nil
}
