package apiv1

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	xoauth2 "golang.org/x/oauth2"
)

const (
	oidcRetryBase = 5 * time.Second
	oidcRetryMax  = 2 * time.Minute
)

// lazyOIDCProvider wraps an OIDC provider discovery with retry-on-failure logic.
// If the IdP is unreachable at startup, the service continues running and retries
// discovery on each request (with exponential backoff) instead of crashing.
type lazyOIDCProvider struct {
	mu sync.RWMutex

	// Configuration (immutable)
	cfg model.APIAuthOIDC
	log *logger.Log

	// Resolved state (populated after successful discovery)
	oauthConfig        *xoauth2.Config
	verifier           *oidc.IDTokenVerifier
	endSessionURL      string
	postLogoutRedirect string

	// Retry state
	retryAfter   time.Time
	retryBackoff time.Duration
	ready        bool
}

func newLazyOIDCProvider(ctx context.Context, cfg model.APIAuthOIDC, log *logger.Log) *lazyOIDCProvider {
	p := &lazyOIDCProvider{
		cfg: cfg,
		log: log,
	}

	// Attempt eager initialization.
	if err := p.discover(ctx); err != nil {
		log.Error(err, "admin_oidc_discovery_failed_will_retry", "issuer", cfg.IssuerURL)
		p.retryBackoff = oidcRetryBase
		p.retryAfter = time.Now().Add(p.retryBackoff)
	}

	return p
}

// discover performs OIDC discovery and populates all fields.
func (p *lazyOIDCProvider) discover(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, p.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed for %s: %w", p.cfg.IssuerURL, err)
	}

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	p.oauthConfig = &xoauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	p.verifier = provider.Verifier(&oidc.Config{
		ClientID: p.cfg.ClientID,
	})

	// Discover end_session_endpoint for RP-initiated logout.
	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&providerClaims); err == nil && providerClaims.EndSessionEndpoint != "" {
		p.endSessionURL = providerClaims.EndSessionEndpoint
	}

	// Derive post-logout redirect from the redirect_uri.
	p.postLogoutRedirect = p.cfg.RedirectURI
	if idx := len(p.postLogoutRedirect) - len("/callback"); idx > 0 && p.postLogoutRedirect[idx:] == "/callback" {
		p.postLogoutRedirect = p.postLogoutRedirect[:idx]
	}

	p.ready = true
	p.retryBackoff = 0
	p.log.Info("admin OIDC provider initialized", "issuer", p.cfg.IssuerURL)
	return nil
}

// ensureReady checks if the provider is initialized and retries if not.
// Returns an error if still not ready (backoff not elapsed or discovery fails again).
func (p *lazyOIDCProvider) ensureReady(ctx context.Context) error {
	p.mu.RLock()
	if p.ready {
		p.mu.RUnlock()
		return nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after lock.
	if p.ready {
		return nil
	}

	if time.Now().Before(p.retryAfter) {
		return fmt.Errorf("OIDC provider not available, next retry at %s", p.retryAfter.Format(time.RFC3339))
	}

	if err := p.discover(ctx); err != nil {
		p.retryBackoff = min(p.retryBackoff*2, oidcRetryMax)
		p.retryAfter = time.Now().Add(p.retryBackoff)
		p.log.Error(err, "admin_oidc_discovery_retry_failed", "issuer", p.cfg.IssuerURL, "next_retry_in", p.retryBackoff.String())
		return err
	}
	return nil
}

// Config returns the OAuth2 config, or nil if not yet ready.
func (p *lazyOIDCProvider) Config(ctx context.Context) (*xoauth2.Config, error) {
	if err := p.ensureReady(ctx); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.oauthConfig, nil
}

// Verifier returns the ID token verifier, or nil if not yet ready.
func (p *lazyOIDCProvider) Verifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if err := p.ensureReady(ctx); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.verifier, nil
}

// EndSessionURL returns the end session URL (empty if not advertised or not ready).
func (p *lazyOIDCProvider) EndSessionURL(ctx context.Context) string {
	if err := p.ensureReady(ctx); err != nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endSessionURL
}

// PostLogoutRedirect returns the computed post-logout redirect URI.
func (p *lazyOIDCProvider) PostLogoutRedirect(ctx context.Context) string {
	if err := p.ensureReady(ctx); err != nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.postLogoutRedirect
}
