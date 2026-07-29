package oidcrp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	pkgoauth2 "github.com/SUNET/vc/pkg/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcRPRetryBase = 5 * time.Second
	oidcRPRetryMax  = 2 * time.Minute
)

// Service provides OIDC Relying Party functionality
type Service struct {
	cfg          *model.OIDCRP
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	sessionCache pkgcache.Cache[*Session]
	dbService    *db.Service
	httpClient   *http.Client
	log          *logger.Log

	// Lazy-init state
	mu           sync.RWMutex
	ready        bool
	retryAfter   time.Time
	retryBackoff time.Duration
}

// New creates a new OIDC RP service
func New(ctx context.Context, cfg *model.OIDCRP, sessionCache pkgcache.Cache[*Session], dbService *db.Service, log *logger.Log) (*Service, error) {
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

	// Attempt eager initialization; if the IdP is unreachable, defer to lazy retry.
	if err := s.initialize(ctx); err != nil {
		s.log.Error(err, "oidcrp_init_failed_will_retry", "issuer", cfg.IssuerURL)
		s.retryBackoff = oidcRPRetryBase
		s.retryAfter = time.Now().Add(s.retryBackoff)
		go s.backgroundDiscovery(ctx)
	}

	return s, nil
}

// initialize performs OIDC discovery and sets up the oauth2 config and verifier.
func (s *Service) initialize(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, s.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider at %s: %w", s.cfg.IssuerURL, err)
	}
	s.provider = provider

	// Resolve client credentials based on registration method
	var clientID, clientSecret string

	if s.cfg.Registration.Preconfigured != nil && s.cfg.Registration.Preconfigured.Enable {
		clientID = s.cfg.Registration.Preconfigured.ClientID
		clientSecret = s.cfg.Registration.Preconfigured.ClientSecret
	} else if s.cfg.Registration.Dynamic != nil && s.cfg.Registration.Dynamic.Enable {
		s.log.Info("Dynamic client registration enabled, attempting registration")

		// Check if we have stored credentials
		storedCreds, err := s.dbService.DynamicRegistrationColl.Get(ctx)
		if err != nil {
			s.log.Info("Failed to load dynamic registration credentials", "error", err)
		}
		if storedCreds != nil {
			s.log.Info("Using stored dynamic registration credentials", "client_id", storedCreds.ClientID)
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
				return fmt.Errorf("failed to get provider metadata: %w", err)
			}

			if providerJSON.RegistrationEndpoint == "" {
				return fmt.Errorf("OIDC provider does not support dynamic client registration (no registration_endpoint in metadata)")
			}

			regResp, err := s.dynamicClientRegistration(ctx, providerJSON.RegistrationEndpoint, regReq, s.cfg.Registration.Dynamic.InitialAccessToken)
			if err != nil {
				return fmt.Errorf("dynamic client registration failed: %w", err)
			}

			clientID = regResp.ClientID
			clientSecret = regResp.ClientSecret

			s.log.Info("Dynamic client registration successful",
				"client_id", clientID,
				"registration_access_token_present", regResp.RegistrationAccessToken != "")

			// Persist credentials
			if err := s.dbService.DynamicRegistrationColl.Save(ctx, &db.DynamicRegistrationCredentials{
				ClientID:                regResp.ClientID,
				ClientSecret:            regResp.ClientSecret,
				RegistrationAccessToken: regResp.RegistrationAccessToken,
				RegistrationClientURI:   regResp.RegistrationClientURI,
				ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
			}); err != nil {
				s.log.Info("Failed to persist dynamic registration credentials", "error", err)
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
		RedirectURL:  s.cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.cfg.Scopes,
	}

	s.ready = true
	s.retryBackoff = 0

	s.log.Info("OIDC RP service initialized",
		"issuer", s.cfg.IssuerURL,
		"client_id", clientID,
		"redirect_uri", s.cfg.RedirectURI,
		"dynamic_registration", s.cfg.Registration.Dynamic != nil && s.cfg.Registration.Dynamic.Enable)

	return nil
}

// ensureReady checks if the service is initialized and retries discovery if not.
func (s *Service) ensureReady(ctx context.Context) error {
	s.mu.RLock()
	if s.ready {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ready {
		return nil
	}

	if time.Now().Before(s.retryAfter) {
		return fmt.Errorf("OIDC RP not available, next retry at %s", s.retryAfter.Format(time.RFC3339))
	}

	if err := s.initialize(ctx); err != nil {
		s.retryBackoff = min(s.retryBackoff*2, oidcRPRetryMax)
		s.retryAfter = time.Now().Add(s.retryBackoff)
		s.log.Error(err, "oidcrp_retry_failed", "issuer", s.cfg.IssuerURL, "next_retry_in", s.retryBackoff.String())
		return err
	}
	return nil
}

// backgroundDiscovery retries OIDC discovery in the background with exponential
// backoff until the OP becomes reachable, then exits.
func (s *Service) backgroundDiscovery(ctx context.Context) {
	backoff := oidcRPRetryBase
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		s.mu.RLock()
		if s.ready {
			s.mu.RUnlock()
			return
		}
		s.mu.RUnlock()

		s.mu.Lock()
		if s.ready {
			s.mu.Unlock()
			return
		}
		if err := s.initialize(ctx); err != nil {
			backoff = min(backoff*2, oidcRPRetryMax)
			s.retryBackoff = backoff
			s.retryAfter = time.Now().Add(backoff)
			s.mu.Unlock()
			s.log.Info("oidcrp_background_discovery_retry", "issuer", s.cfg.IssuerURL, "next_retry_in", backoff.String())
			continue
		}
		s.mu.Unlock()
		s.log.Info("OIDC OP is now reachable", "issuer", s.cfg.IssuerURL)
		return
	}
}

// AuthRequest represents an OIDC authentication request
type AuthRequest struct {
	AuthorizationURL string
	State            string
}

// InitiateAuth initiates an OIDC authentication flow.
// oidcParams and dynamicParams are optional: when non-nil, they customize the
// authorization request (e.g., acr_values, claims parameter, extra scopes).
func (s *Service) InitiateAuth(ctx context.Context, credentialType string, oidcParams *model.OIDCRequestParams, dynamicParams map[string]string) (*AuthRequest, error) {
	if err := s.ensureReady(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

	s.log.Debug("Initiating OIDC auth",
		"credential_type", credentialType)

	// Create session with state, nonce, and PKCE verifier
	session, err := s.createSession(ctx, credentialType)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Store dynamic params in session for later retrieval during policy evaluation
	if len(dynamicParams) > 0 {
		session.DynamicParams = dynamicParams
		s.sessionCache.Set(ctx, session.ID, session)
	}

	// Generate PKCE code_challenge from code_verifier
	codeChallenge := pkgoauth2.CreateCodeChallenge(pkgoauth2.CodeChallengeMethodS256, session.CodeVerifier)

	// Build authorization URL with PKCE
	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", session.Nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}

	// Apply per-scope OIDC request parameters
	if oidcParams != nil {
		extraOpts, err := resolveOIDCRequestParams(oidcParams, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC request params: %w", err)
		}
		authOpts = append(authOpts, extraOpts...)
	}

	// If extra scopes are configured, create a temporary config with merged scopes
	oauthCfg := s.oauth2Config
	if oidcParams != nil && len(oidcParams.ExtraScopes) > 0 {
		mergedScopes := make([]string, len(s.oauth2Config.Scopes))
		copy(mergedScopes, s.oauth2Config.Scopes)
		mergedScopes = append(mergedScopes, oidcParams.ExtraScopes...)
		oauthCfg = &oauth2.Config{
			ClientID:     s.oauth2Config.ClientID,
			ClientSecret: s.oauth2Config.ClientSecret,
			RedirectURL:  s.oauth2Config.RedirectURL,
			Endpoint:     s.oauth2Config.Endpoint,
			Scopes:       mergedScopes,
		}
	}

	authURL := oauthCfg.AuthCodeURL(session.State, authOpts...)

	s.log.Debug("OIDC authorization URL generated",
		"credential_type", credentialType,
		"state", session.State)

	return &AuthRequest{
		AuthorizationURL: authURL,
		State:            session.State,
	}, nil
}

// InitiateAuthForVCI initiates an OIDC authentication flow that is linked to
// an OpenID4VCI credential issuance session. The VCI session ID is stored in
// the OIDC session so that the callback handler can route the result back into
// the VCI pipeline.
func (s *Service) InitiateAuthForVCI(ctx context.Context, credentialType, vciSessionID string, oidcParams *model.OIDCRequestParams, dynamicParams map[string]string) (*AuthRequest, error) {
	authReq, err := s.InitiateAuth(ctx, credentialType, oidcParams, dynamicParams)
	if err != nil {
		return nil, err
	}

	// Update the OIDC session with VCI linkage
	session, err := s.getSession(ctx, authReq.State)
	if err != nil {
		return nil, fmt.Errorf("failed to update OIDC session with VCI context: %w", err)
	}

	session.VCISessionID = vciSessionID
	s.sessionCache.Set(ctx, session.ID, session)

	s.log.Info("OIDC auth initiated for VCI flow",
		"oidc_state", authReq.State,
		"vci_session_id", vciSessionID,
		"credential_type", credentialType)

	return authReq, nil
}

// reservedOIDCParams are authorization request parameters that CustomParams
// must not be allowed to set, since oauth2.AuthCodeOption values are applied
// by key (last write wins) - letting an operator-configured custom param
// collide with one of these would silently override state/nonce/PKCE
// guarantees set earlier in BuildAuthorizationURL.
var reservedOIDCParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"scope":                 true,
	"state":                 true,
	"nonce":                 true,
	"code_challenge":        true,
	"code_challenge_method": true,
}

// resolveOIDCRequestParams resolves template variables in OIDC request params
// and returns oauth2.AuthCodeOption values to append to the authorization URL.
func resolveOIDCRequestParams(params *model.OIDCRequestParams, dynamicParams map[string]string) ([]oauth2.AuthCodeOption, error) {
	var opts []oauth2.AuthCodeOption

	if params.ACRValues != "" {
		resolved, err := resolveTemplate(params.ACRValues, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("acr_values template: %w", err)
		}
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", resolved))
	}

	if params.Claims != "" {
		resolved, err := resolveTemplate(params.Claims, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("claims template: %w", err)
		}
		opts = append(opts, oauth2.SetAuthURLParam("claims", resolved))
	}

	for key, value := range params.CustomParams {
		if reservedOIDCParams[key] {
			return nil, fmt.Errorf("custom_params key %q is reserved and cannot override a core authorization request parameter", key)
		}
		resolvedValue, err := resolveTemplate(value, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("custom param %q template: %w", key, err)
		}
		opts = append(opts, oauth2.SetAuthURLParam(key, resolvedValue))
	}

	return opts, nil
}

// resolveTemplate resolves Go template syntax in a string using dynamic params as data.
func resolveTemplate(tmplStr string, data map[string]string) (string, error) {
	if len(data) == 0 {
		return tmplStr, nil
	}

	tmpl, err := template.New("param").Option("missingkey=error").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("invalid template %q: %w", tmplStr, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution failed for %q: %w", tmplStr, err)
	}
	return buf.String(), nil
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
	if err := s.ensureReady(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

	s.log.Debug("ProcessCallback", "state", state)

	// Retrieve and validate session
	session, err := s.getSession(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Exchange authorization code for tokens with PKCE
	s.log.Debug("ProcessCallback: exchanging authorization code", "state", state)
	oauth2Token, err := s.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier),
	)
	if err != nil {
		s.log.Debug("ProcessCallback: code exchange failed", "state", state, "error", err)
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	s.log.Debug("ProcessCallback: code exchange successful", "state", state)

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.log.Debug("ProcessCallback: no id_token in token response", "state", state)
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("no id_token in token response")
	}

	s.log.Debug("ProcessCallback: verifying ID token", "state", state)
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.log.Debug("ProcessCallback: ID token verification failed", "state", state, "error", err)
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
		"issuer", idToken.Issuer,
	)

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

// BuildTransformer creates a claim transformer from the configuration.
// Returns nil if no attribute_mapping is configured (OIDC claims pass through as-is).
func (s *Service) BuildTransformer() *ClaimTransformer {
	if s.cfg == nil || len(s.cfg.AttributeMapping) == 0 {
		return nil
	}

	return NewClaimTransformer(s.cfg.AttributeMapping)
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
		return nil, fmt.Errorf("session not found or expired")
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
	if err := s.ensureReady(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

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
