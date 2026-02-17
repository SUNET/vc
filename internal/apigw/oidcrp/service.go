//go:build oidcrp

package oidcrp

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"vc/internal/apigw/db"
	pkgcache "vc/pkg/cache"
	"vc/pkg/crypto"
	"vc/pkg/logger"
	"vc/pkg/model"
	pkgoauth2 "vc/pkg/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Service provides OIDC Relying Party functionality
type Service struct {
	cfg          *model.OIDCRPConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	sessionCache pkgcache.Cache[*Session]
	dbService    *db.Service
	httpClient   *http.Client
	log          *logger.Log
}

// New creates a new OIDC RP service
func New(ctx context.Context, cfg *model.OIDCRPConfig, sessionCache pkgcache.Cache[*Session], dbService *db.Service, log *logger.Log) (*Service, error) {
	if !cfg.Enable {
		log.Info("OIDC RP support disabled")
		return nil, nil
	}

	s := &Service{
		cfg:          cfg,
		sessionCache: sessionCache,
		dbService:    dbService,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		log:          log.New("oidcrp"),
	}

	// Initialize OIDC Provider (performs discovery)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.IssuerURL, err)
	}
	s.provider = provider

	// Resolve client credentials based on registration method
	var clientID, clientSecret string

	if cfg.Registration.Preconfigured != nil && cfg.Registration.Preconfigured.Enable {
		clientID = cfg.Registration.Preconfigured.ClientID
		clientSecret = cfg.Registration.Preconfigured.ClientSecret
	} else if cfg.Registration.Dynamic.Enable {
		log.Info("Dynamic client registration enabled, attempting registration")

		// Check if we have stored credentials
		storedCreds, err := s.dbService.VCDynamicRegistrationColl.Get(ctx)
		if err != nil {
			log.Info("Failed to load dynamic registration credentials", "error", err)
		}
		if storedCreds != nil {
			log.Info("Using stored dynamic registration credentials", "client_id", storedCreds.ClientID)
			clientID = storedCreds.ClientID
			clientSecret = storedCreds.ClientSecret
		} else {
			// Perform dynamic registration
			regReq := s.buildRegistrationRequest()

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

			regResp, err := s.dynamicClientRegistration(ctx, providerJSON.RegistrationEndpoint, regReq, cfg.Registration.Dynamic.InitialAccessToken)
			if err != nil {
				return nil, fmt.Errorf("dynamic client registration failed: %w", err)
			}

			clientID = regResp.ClientID
			clientSecret = regResp.ClientSecret

			log.Info("Dynamic client registration successful",
				"client_id", clientID,
				"registration_access_token_present", regResp.RegistrationAccessToken != "")

			// Persist credentials
			if err := s.dbService.VCDynamicRegistrationColl.Save(ctx, &db.DynamicRegistrationCredentials{
				ClientID:                regResp.ClientID,
				ClientSecret:            regResp.ClientSecret,
				RegistrationAccessToken: regResp.RegistrationAccessToken,
				RegistrationClientURI:   regResp.RegistrationClientURI,
				ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
			}); err != nil {
				log.Info("Failed to persist dynamic registration credentials", "error", err)
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

	s.log.Info("OIDC RP service initialized",
		"issuer", cfg.IssuerURL,
		"client_id", clientID,
		"redirect_uri", cfg.RedirectURI,
		"dynamic_registration", cfg.Registration.Dynamic.Enable)

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
	session, err := s.createSession(ctx, credentialType)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate PKCE code_challenge from code_verifier
	codeChallenge := pkgoauth2.CreateCodeChallenge(pkgoauth2.CodeChallengeMethodS256, session.CodeVerifier)

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
	session, err := s.getSession(ctx, state)
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
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if nonce, ok := claims["nonce"].(string); !ok || nonce != session.Nonce {
		s.deleteSession(ctx, state)
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
func (s *Service) GetSession(ctx context.Context, state string) (*Session, error) {
	return s.getSession(ctx, state)
}

// DeleteSession removes a session
func (s *Service) DeleteSession(ctx context.Context, state string) {
	s.deleteSession(ctx, state)
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

// createSession creates a new session with generated state, nonce, and PKCE code_verifier.
func (s *Service) createSession(ctx context.Context, credentialType string) (*Session, error) {
	state, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	codeVerifier, err := pkgoauth2.CreateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code_verifier: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:             state,
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		CredentialType: credentialType,
		IssuerURL:      s.cfg.IssuerURL,
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(s.cfg.SessionDuration) * time.Second),
	}

	s.sessionCache.Set(ctx, session.ID, session)

	s.log.Debug("session created",
		"session_id", session.ID,
		"credential_type", credentialType,
		"issuer", s.cfg.IssuerURL)

	return session, nil
}

// getSession retrieves a session by state parameter.
func (s *Service) getSession(ctx context.Context, state string) (*Session, error) {
	session, ok := s.sessionCache.Get(ctx, state)
	if !ok || session == nil {
		return nil, fmt.Errorf("session not found or expired for state: %s", state)
	}

	return session, nil
}

// deleteSession removes a session.
func (s *Service) deleteSession(ctx context.Context, state string) {
	s.sessionCache.Delete(ctx, state)
	s.log.Debug("session deleted", "state", state)
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
