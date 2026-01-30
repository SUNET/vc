//go:build oidcrp

package oidcrp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Service provides OIDC Relying Party functionality
type Service struct {
	cfg          *model.OIDCRPConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	sessionStore *SessionStore
	log          *logger.Log
}

// New creates a new OIDC RP service
func New(ctx context.Context, cfg *model.OIDCRPConfig, log *logger.Log) (*Service, error) {
	if !cfg.Enabled {
		log.Info("OIDC RP support disabled")
		return nil, nil
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid OIDC RP configuration: %w", err)
	}

	s := &Service{
		cfg: cfg,
		log: log.New("oidcrp"),
	}

	// Initialize OIDC Provider (performs discovery)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.IssuerURL, err)
	}
	s.provider = provider

	// Handle dynamic client registration if enabled
	clientID := cfg.ClientID
	clientSecret := cfg.ClientSecret

	if cfg.DynamicRegistration.Enabled {
		log.Info("Dynamic client registration enabled, attempting registration")

		// Check if we have cached credentials
		cachedCreds, err := loadCachedCredentials(cfg.DynamicRegistration.StoragePath)
		if err == nil && cachedCreds != nil {
			log.Info("Using cached dynamic registration credentials", "client_id", cachedCreds.ClientID)
			clientID = cachedCreds.ClientID
			clientSecret = cachedCreds.ClientSecret
		} else {
			// Perform dynamic registration
			regClient := NewDynamicRegistrationClient(log)
			regReq := BuildRegistrationRequest(cfg)

			// Get registration endpoint from provider metadata
			var providerJSON struct {
				RegistrationEndpoint string `json:"registration_endpoint"`
			}
			if err := provider.Claims(&providerJSON); err != nil {
				return nil, fmt.Errorf("failed to get provider metadata: %w", err)
			}

			if providerJSON.RegistrationEndpoint == "" {
				return nil, fmt.Errorf("OIDC provider does not support dynamic client registration (no registration_endpoint in metadata)")
			}

			regResp, err := regClient.Register(ctx, providerJSON.RegistrationEndpoint, regReq, cfg.DynamicRegistration.InitialAccessToken)
			if err != nil {
				return nil, fmt.Errorf("dynamic client registration failed: %w", err)
			}

			clientID = regResp.ClientID
			clientSecret = regResp.ClientSecret

			log.Info("Dynamic client registration successful",
				"client_id", clientID,
				"registration_access_token_present", regResp.RegistrationAccessToken != "")

			// Cache credentials if storage path is provided
			if cfg.DynamicRegistration.StoragePath != "" {
				if err := saveCachedCredentials(cfg.DynamicRegistration.StoragePath, regResp); err != nil {
					log.Info("Failed to cache dynamic registration credentials", "error", err)
				}
			}
		}
	}

	// Create ID token verifier
	s.verifier = provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Configure OAuth2
	s.oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	// Initialize session store
	sessionDuration := time.Duration(cfg.SessionDuration) * time.Second
	if sessionDuration == 0 {
		sessionDuration = 3600 * time.Second // Default 1 hour
	}
	s.sessionStore = NewSessionStore(sessionDuration, s.log)

	s.log.Info("OIDC RP service initialized",
		"issuer", cfg.IssuerURL,
		"client_id", clientID,
		"redirect_uri", cfg.RedirectURI,
		"dynamic_registration", cfg.DynamicRegistration.Enabled)

	return s, nil
}

// AuthRequest represents an OIDC authentication request
type AuthRequest struct {
	AuthorizationURL string
	State            string
}

// InitiateAuth initiates an OIDC authentication flow
func (s *Service) InitiateAuth(ctx context.Context, credentialType string) (*AuthRequest, error) {
	// Validate credential type exists in configuration
	credMapping, exists := s.cfg.CredentialMappings[credentialType]
	if !exists {
		return nil, fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	s.log.Debug("Initiating OIDC auth",
		"credential_type", credentialType,
		"credential_config_id", credMapping.CredentialConfigID)

	// Create session with state, nonce, and PKCE verifier
	session, err := s.sessionStore.Create(credentialType, s.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate PKCE code_challenge from code_verifier
	codeChallenge := generateCodeChallenge(session.CodeVerifier)

	// Build authorization URL with PKCE
	authURL := s.oauth2Config.AuthCodeURL(
		session.State,
		oauth2.SetAuthURLParam("nonce", session.Nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	s.log.Info("OIDC authorization URL generated",
		"credential_type", credentialType,
		"state", session.State)

	return &AuthRequest{
		AuthorizationURL: authURL,
		State:            session.State,
	}, nil
}

// AuthResponse represents the result of OIDC authentication
type AuthResponse struct {
	IDToken      *oidc.IDToken
	AccessToken  string
	RefreshToken string
	Claims       map[string]any
	SessionID    string
}

// ProcessCallback processes the OIDC provider callback
func (s *Service) ProcessCallback(ctx context.Context, code, state string) (*AuthResponse, error) {
	// Retrieve and validate session
	session, err := s.sessionStore.Get(state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Exchange authorization code for tokens with PKCE
	oauth2Token, err := s.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier),
	)
	if err != nil {
		s.sessionStore.Delete(state)
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.sessionStore.Delete(state)
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.sessionStore.Delete(state)
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		s.sessionStore.Delete(state)
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if nonce, ok := claims["nonce"].(string); !ok || nonce != session.Nonce {
		s.sessionStore.Delete(state)
		return nil, fmt.Errorf("nonce mismatch")
	}

	s.log.Info("OIDC authentication successful",
		"subject", idToken.Subject,
		"issuer", idToken.Issuer)

	return &AuthResponse{
		IDToken:      idToken,
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		Claims:       claims,
		SessionID:    session.ID,
	}, nil
}

// GetSession retrieves a session by state
func (s *Service) GetSession(state string) (*Session, error) {
	return s.sessionStore.Get(state)
}

// DeleteSession removes a session
func (s *Service) DeleteSession(state string) {
	s.sessionStore.Delete(state)
}

// BuildTransformer creates a claim transformer from the configuration
func (s *Service) BuildTransformer() (*ClaimTransformer, error) {
	if s.cfg == nil {
		return nil, fmt.Errorf("OIDC RP configuration is nil")
	}

	if len(s.cfg.CredentialMappings) == 0 {
		return nil, fmt.Errorf("no credential mappings configured")
	}

	return &ClaimTransformer{
		Mappings: s.cfg.CredentialMappings,
	}, nil
}

// generateCodeChallenge generates PKCE code_challenge from code_verifier
func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// GetUserInfo fetches additional claims from the UserInfo endpoint
func (s *Service) GetUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	userInfo, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	var claims map[string]any
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	return claims, nil
}
