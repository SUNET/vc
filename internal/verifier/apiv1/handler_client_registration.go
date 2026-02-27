package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vc/internal/verifier/db"

	"golang.org/x/crypto/bcrypt"
)

// ClientRegistrationRequest represents RFC 7591 client registration request
type ClientRegistrationRequest struct {
	// REQUIRED or OPTIONAL OAuth 2.0 parameters
	RedirectURIs            []string `json:"redirect_uris,omitempty" validate:"required,min=1,dive,redirect_uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty" default:"client_secret_basic" validate:"omitempty,oneof=client_secret_basic client_secret_post none"`
	GrantTypes              []string `json:"grant_types,omitempty" default:"[\"authorization_code\"]" validate:"omitempty,dive,oneof=authorization_code refresh_token"`
	ResponseTypes           []string `json:"response_types,omitempty" default:"[\"code\"]" validate:"omitempty,dive,oneof=code"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty" validate:"omitempty,httpsurl"`
	LogoURI                 string   `json:"logo_uri,omitempty" validate:"omitempty,httpsurl"`
	Scope                   string   `json:"scope,omitempty" default:"openid"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty" validate:"omitempty,httpsurl"`
	PolicyURI               string   `json:"policy_uri,omitempty" validate:"omitempty,httpsurl"`
	JWKSUri                 string   `json:"jwks_uri,omitempty" validate:"omitempty,excluded_with=JWKS"`
	JWKS                    any      `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`

	// OpenID Connect specific
	ApplicationType         string   `json:"application_type,omitempty" default:"web" validate:"omitempty,oneof=web native"`
	SectorIdentifierURI     string   `json:"sector_identifier_uri,omitempty"`
	SubjectType             string   `json:"subject_type,omitempty" default:"public" validate:"omitempty,oneof=public pairwise"`
	IDTokenSignedRespAlg    string   `json:"id_token_signed_response_alg,omitempty" default:"RS256"`
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
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" default:"S256" validate:"omitempty,oneof=S256 plain"`
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

// RegisterClient handles dynamic client registration (RFC 7591)
func (c *Client) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:register_client")
	defer span.End()

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
	registrationClientURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "register", clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to construct registration client URI: %w", err)
	}

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

// ClientInformationResponse represents RFC 7592 client information response (GET)
type ClientInformationResponse struct {
	ClientRegistrationResponse
}

// GetClientInformationRequest represents a request to get client information
type GetClientInformationRequest struct {
	ClientID                string `json:"-" uri:"client_id" validate:"required,max=128,printascii"`
	RegistrationAccessToken string `json:"-" header:"Authorization" validate:"required"`
}

// GetClientInformation retrieves client configuration (RFC 7592)
func (c *Client) GetClientInformation(ctx context.Context, req *GetClientInformationRequest) (*ClientInformationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_client_information")
	defer span.End()

	// Extract bearer token from Authorization header
	registrationAccessToken := extractBearerToken(req.RegistrationAccessToken)

	// Get client from database
	client, err := c.db.Clients.GetByClientID(ctx, req.ClientID)
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

	registrationClientURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "register", req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to construct registration client URI: %w", err)
	}

	response := &ClientInformationResponse{
		ClientRegistrationResponse: ClientRegistrationResponse{
			ClientID:                req.ClientID,
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
			RegistrationClientURI:   registrationClientURI,
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

// DeleteClientRequest represents a request to delete a client
type DeleteClientRequest struct {
	ClientID                string `json:"-" uri:"client_id" validate:"required,max=128,printascii"`
	RegistrationAccessToken string `json:"-" header:"Authorization" validate:"required"`
}

// DeleteClient deletes a client registration (RFC 7592)
func (c *Client) DeleteClient(ctx context.Context, req *DeleteClientRequest) error {
	ctx, span := c.tracer.Start(ctx, "apiv1:delete_client")
	defer span.End()

	// Extract bearer token from Authorization header
	registrationAccessToken := extractBearerToken(req.RegistrationAccessToken)

	// Get existing client
	client, err := c.db.Clients.GetByClientID(ctx, req.ClientID)
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
	return c.db.Clients.Delete(ctx, req.ClientID)
}

// UpdateClientRequest represents a request to update client configuration
type UpdateClientRequest struct {
	ClientID                string `json:"-" uri:"client_id" validate:"required,max=128,printascii"`
	RegistrationAccessToken string `json:"-" header:"Authorization" validate:"required"`
	ClientRegistrationRequest
}

// UpdateClient updates client configuration (RFC 7592)
func (c *Client) UpdateClient(ctx context.Context, req *UpdateClientRequest) (*ClientRegistrationResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:update_client")
	defer span.End()

	// Extract bearer token from Authorization header
	registrationAccessToken := extractBearerToken(req.RegistrationAccessToken)

	// Get existing client
	client, err := c.db.Clients.GetByClientID(ctx, req.ClientID)
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

	clientReg := &req.ClientRegistrationRequest

	// Update client fields
	if clientReg.RedirectURIs != nil {
		client.RedirectURIs = clientReg.RedirectURIs
	}
	if clientReg.GrantTypes != nil {
		client.GrantTypes = clientReg.GrantTypes
	}
	if clientReg.ResponseTypes != nil {
		client.ResponseTypes = clientReg.ResponseTypes
	}
	if clientReg.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = clientReg.TokenEndpointAuthMethod
	}
	if clientReg.Scope != "" {
		client.AllowedScopes = strings.Split(clientReg.Scope, " ")
	}
	if clientReg.SubjectType != "" {
		client.SubjectType = clientReg.SubjectType
	}
	if clientReg.JWKSUri != "" {
		client.JWKSUri = clientReg.JWKSUri
	}
	if clientReg.JWKS != nil {
		client.JWKS = clientReg.JWKS
	}
	if clientReg.ClientName != "" {
		client.ClientName = clientReg.ClientName
	}
	if clientReg.ClientURI != "" {
		client.ClientURI = clientReg.ClientURI
	}
	if clientReg.LogoURI != "" {
		client.LogoURI = clientReg.LogoURI
	}
	if clientReg.Contacts != nil {
		client.Contacts = clientReg.Contacts
	}
	if clientReg.TosURI != "" {
		client.TosURI = clientReg.TosURI
	}
	if clientReg.PolicyURI != "" {
		client.PolicyURI = clientReg.PolicyURI
	}
	if clientReg.CodeChallengeMethod != "" {
		client.CodeChallengeMethod = clientReg.CodeChallengeMethod
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

	registrationClientURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "register", req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to construct registration client URI: %w", err)
	}

	response := &ClientRegistrationResponse{
		ClientID:                req.ClientID,
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
		RegistrationClientURI:   registrationClientURI,
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

// extractBearerToken extracts the token from a "Bearer <token>" Authorization header value
func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}
