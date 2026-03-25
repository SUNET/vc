package oidcrp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"github.com/SUNET/vc/pkg/model"
)

// RegistrationRequest represents RFC 7591 client registration request
type RegistrationRequest struct {
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

// RegistrationResponse represents RFC 7591 client registration response
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"` // 0 = never expires
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

// dynamicClientRegistration performs dynamic client registration with an OIDC Provider (RFC 7591)
func (s *Service) dynamicClientRegistration(ctx context.Context, registrationEndpoint string, req *RegistrationRequest, initialAccessToken string) (*RegistrationResponse, error) {
	s.log.Info("Performing dynamic client registration", "endpoint", registrationEndpoint)

	// Marshal request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", registrationEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add initial access token if provided (some OPs require it)
	if initialAccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+initialAccessToken)
	}

	// Send request
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body with a size limit to prevent OOM from malicious endpoints
	const maxResponseSize = 1 << 20 // 1 MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		s.log.Error(nil, "Registration failed", "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var registrationResp RegistrationResponse
	if err := json.Unmarshal(respBody, &registrationResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	s.log.Info("Dynamic client registration successful",
		"client_id", registrationResp.ClientID,
		"has_secret", registrationResp.ClientSecret != "")

	return &registrationResp, nil
}

// buildRegistrationRequest creates a registration request from the service's OIDC RP config
func (s *Service) buildRegistrationRequest() *RegistrationRequest {
	return &RegistrationRequest{
		RedirectURIs:            []string{s.cfg.RedirectURI},
		TokenEndpointAuthMethod: "client_secret_basic", // Default method
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              s.cfg.ClientName,
		ClientURI:               s.cfg.ClientURI,
		LogoURI:                 s.cfg.LogoURI,
		Scope:                   joinScopes(s.cfg.Scopes),
		Contacts:                s.cfg.Contacts,
		TosURI:                  s.cfg.TosURI,
		PolicyURI:               s.cfg.PolicyURI,
		ApplicationType:         "web",
		CodeChallengeMethod:     "S256", // Always use PKCE with S256
		SoftwareID:              "SUNET-vc-issuer",
		SoftwareVersion:         model.BuildVersion,
	}
}

// joinScopes converts scope slice to space-separated string
func joinScopes(scopes []string) string {
	var result strings.Builder
	for i, scope := range scopes {
		if i > 0 {
			result.WriteString(" ")
		}
		result.WriteString(scope)
	}
	return result.String()
}
