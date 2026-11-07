package httphelpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/resourcereach"
	"github.com/SUNET/vc/pkg/spocputil"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// JWKSCache is the generic cache interface used to store raw JWKS JSON.
// It is satisfied by both MemoryCache and MongoCache from pkg/cache.
type JWKSCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte)
}

// getKeys retrieves the JWKS keyset, using the cache for the raw JSON.
// On cache miss it fetches from the URL and stores the result.
func getKeys(ctx context.Context, url string, c JWKSCache, log func(string, ...any)) (jwk.Set, error) {
	// Try cache first.
	if raw, ok := c.Get(ctx, url); ok {
		set, err := jwk.Parse(raw)
		if err == nil {
			return set, nil
		}
		// Cached data is corrupt – fall through to re-fetch.
		log("jwks_cache_parse_failed, re-fetching", "error", err, "url", url)
	}

	// Fetch from remote.
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", url, err)
	}

	// Serialize and store in cache.
	raw, err := json.Marshal(set)
	if err == nil {
		c.Set(ctx, url, raw)
	} else {
		log("jwks_marshal_for_cache_failed", "error", err, "url", url)
	}

	log("jwks_refreshed", "url", url, "key_count", set.Len())
	return set, nil
}

// KeySetProvider provides a parsed JWKS keyset. Implementations handle
// caching, refresh, and the underlying source (URL or file) transparently.
type KeySetProvider interface {
	GetKeySet(ctx context.Context) (jwk.Set, error)
}

// jwksRefreshInterval is how often the URL-based JWKS cache re-fetches keys.
const jwksRefreshInterval = 5 * time.Minute

// jwksRetryBaseInterval is the initial backoff for retrying JWKS fetch after init failure.
const jwksRetryBaseInterval = 5 * time.Second

// jwksRetryMaxInterval caps the exponential backoff for JWKS retries.
const jwksRetryMaxInterval = 2 * time.Minute

// urlKeySetProvider caches a parsed jwk.Set fetched from a URL and periodically
// refreshes it to pick up key rotations. It supports lazy initialization: if the
// initial fetch fails, subsequent GetKeySet calls will retry with exponential backoff.
type urlKeySetProvider struct {
	mu           sync.RWMutex
	url          string
	set          jwk.Set
	fetchedAt    time.Time
	rawCache     JWKSCache
	log          func(string, ...any)
	retryAfter   time.Time     // earliest time to retry after a failure
	retryBackoff time.Duration // current backoff duration
}

// newURLKeySetProvider creates a provider. It attempts an eager fetch; if that fails
// the provider is still returned (with nil set) and will retry lazily on GetKeySet calls.
func newURLKeySetProvider(ctx context.Context, url string, rawCache JWKSCache, log func(string, ...any)) *urlKeySetProvider {
	p := &urlKeySetProvider{url: url, rawCache: rawCache, log: log}
	set, err := getKeys(ctx, url, rawCache, log)
	if err != nil {
		log("jwks_initial_fetch_failed_will_retry", "error", err, "url", url)
		p.retryBackoff = jwksRetryBaseInterval
		p.retryAfter = time.Now().Add(p.retryBackoff)
		return p
	}
	p.set = set
	p.fetchedAt = time.Now()
	return p
}

// GetKeySet returns the cached keyset. If not yet initialized (lazy mode), it
// retries with exponential backoff. If the TTL has expired it refreshes to pick
// up key rotations. On refresh failure the stale set is returned.
func (p *urlKeySetProvider) GetKeySet(ctx context.Context) (jwk.Set, error) {
	p.mu.RLock()
	if p.set != nil && time.Since(p.fetchedAt) < jwksRefreshInterval {
		defer p.mu.RUnlock()
		return p.set, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Not yet initialized — retry with backoff.
	if p.set == nil {
		if time.Now().Before(p.retryAfter) {
			return nil, fmt.Errorf("JWKS not available, next retry at %s", p.retryAfter.Format(time.RFC3339))
		}
		set, err := getKeys(ctx, p.url, p.rawCache, p.log)
		if err != nil {
			p.retryBackoff = min(p.retryBackoff*2, jwksRetryMaxInterval)
			p.retryAfter = time.Now().Add(p.retryBackoff)
			p.log("jwks_retry_failed", "error", err, "url", p.url, "next_retry_in", p.retryBackoff.String())
			return nil, fmt.Errorf("JWKS fetch failed: %w", err)
		}
		p.set = set
		p.fetchedAt = time.Now()
		p.retryBackoff = 0
		p.log("jwks_lazy_init_succeeded", "url", p.url, "key_count", set.Len())
		return p.set, nil
	}

	// Already initialized — double-check TTL after lock acquisition.
	if time.Since(p.fetchedAt) < jwksRefreshInterval {
		return p.set, nil
	}

	set, err := getKeys(ctx, p.url, p.rawCache, p.log)
	if err != nil {
		// Return stale keys rather than failing the request.
		p.log("jwks_refresh_failed_using_stale", "error", err, "url", p.url)
		return p.set, nil
	}
	p.set = set
	p.fetchedAt = time.Now()
	return p.set, nil
}

// fileKeySetProvider caches a parsed JWKS loaded from a local file and refreshes
// it only when the file's modification time changes.
type fileKeySetProvider struct {
	mu      sync.RWMutex
	path    string
	set     jwk.Set
	modTime time.Time
}

// newFileKeySetProvider creates a provider that loads and watches the given JWKS file.
func newFileKeySetProvider(path string) (*fileKeySetProvider, error) {
	p := &fileKeySetProvider{path: filepath.Clean(path)}
	if err := p.refresh(); err != nil {
		return nil, err
	}
	return p, nil
}

// GetKeySet returns the cached keyset, re-reading from disk only if the file changed.
func (p *fileKeySetProvider) GetKeySet(_ context.Context) (jwk.Set, error) {
	info, err := os.Stat(p.path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat JWKS file %s: %w", p.path, err)
	}

	p.mu.RLock()
	if p.set != nil && info.ModTime().Equal(p.modTime) {
		defer p.mu.RUnlock()
		return p.set, nil
	}
	p.mu.RUnlock()

	// File changed — reload under write lock.
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock.
	if p.set != nil && info.ModTime().Equal(p.modTime) {
		return p.set, nil
	}

	if err := p.refreshLocked(info.ModTime()); err != nil {
		return nil, err
	}
	return p.set, nil
}

func (p *fileKeySetProvider) refresh() error {
	info, err := os.Stat(p.path)
	if err != nil {
		return fmt.Errorf("failed to stat JWKS file %s: %w", p.path, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshLocked(info.ModTime())
}

func (p *fileKeySetProvider) refreshLocked(modTime time.Time) error {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("failed to read JWKS file %s: %w", p.path, err)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS file %s: %w", p.path, err)
	}
	p.set = set
	p.modTime = modTime
	return nil
}

// oidcKeySetProvider combines OIDC discovery with JWKS fetching. It performs
// discovery lazily (with backoff) so a temporarily-unreachable IdP doesn't
// prevent startup.
type oidcKeySetProvider struct {
	mu           sync.RWMutex
	issuerURL    string
	jwksURL      string // populated after successful discovery
	set          jwk.Set
	fetchedAt    time.Time
	rawCache     JWKSCache
	log          func(string, ...any)
	retryAfter   time.Time
	retryBackoff time.Duration
}

func newOIDCKeySetProvider(ctx context.Context, issuerURL string, rawCache JWKSCache, log func(string, ...any)) *oidcKeySetProvider {
	p := &oidcKeySetProvider{issuerURL: issuerURL, rawCache: rawCache, log: log}

	// Attempt eager discovery + fetch.
	jwksURL, err := discoverJWKSURL(ctx, issuerURL)
	if err != nil {
		log("oidc_discovery_failed_will_retry", "error", err, "issuer", issuerURL)
		p.retryBackoff = jwksRetryBaseInterval
		p.retryAfter = time.Now().Add(p.retryBackoff)
		return p
	}
	p.jwksURL = jwksURL

	set, err := getKeys(ctx, jwksURL, rawCache, log)
	if err != nil {
		log("oidc_jwks_fetch_failed_will_retry", "error", err, "jwks_uri", jwksURL)
		p.retryBackoff = jwksRetryBaseInterval
		p.retryAfter = time.Now().Add(p.retryBackoff)
		return p
	}
	p.set = set
	p.fetchedAt = time.Now()
	log("oidc_provider_ready", "issuer", issuerURL, "jwks_uri", jwksURL, "key_count", set.Len())
	return p
}

func (p *oidcKeySetProvider) GetKeySet(ctx context.Context) (jwk.Set, error) {
	p.mu.RLock()
	if p.set != nil && time.Since(p.fetchedAt) < jwksRefreshInterval {
		defer p.mu.RUnlock()
		return p.set, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Not yet initialized — retry discovery + fetch with backoff.
	if p.set == nil {
		if time.Now().Before(p.retryAfter) {
			return nil, fmt.Errorf("OIDC JWKS not available, next retry at %s", p.retryAfter.Format(time.RFC3339))
		}
		if p.jwksURL == "" {
			jwksURL, err := discoverJWKSURL(ctx, p.issuerURL)
			if err != nil {
				p.retryBackoff = min(p.retryBackoff*2, jwksRetryMaxInterval)
				p.retryAfter = time.Now().Add(p.retryBackoff)
				p.log("oidc_discovery_retry_failed", "error", err, "issuer", p.issuerURL, "next_retry_in", p.retryBackoff.String())
				return nil, fmt.Errorf("OIDC discovery failed: %w", err)
			}
			p.jwksURL = jwksURL
			p.log("oidc_discovery_succeeded", "issuer", p.issuerURL, "jwks_uri", jwksURL)
		}
		set, err := getKeys(ctx, p.jwksURL, p.rawCache, p.log)
		if err != nil {
			p.retryBackoff = min(p.retryBackoff*2, jwksRetryMaxInterval)
			p.retryAfter = time.Now().Add(p.retryBackoff)
			p.log("oidc_jwks_retry_failed", "error", err, "jwks_uri", p.jwksURL, "next_retry_in", p.retryBackoff.String())
			return nil, fmt.Errorf("OIDC JWKS fetch failed: %w", err)
		}
		p.set = set
		p.fetchedAt = time.Now()
		p.retryBackoff = 0
		p.log("oidc_lazy_init_succeeded", "issuer", p.issuerURL, "jwks_uri", p.jwksURL, "key_count", set.Len())
		return p.set, nil
	}

	// Already initialized — refresh if TTL expired.
	if time.Since(p.fetchedAt) < jwksRefreshInterval {
		return p.set, nil
	}

	set, err := getKeys(ctx, p.jwksURL, p.rawCache, p.log)
	if err != nil {
		p.log("oidc_jwks_refresh_failed_using_stale", "error", err, "jwks_uri", p.jwksURL)
		return p.set, nil
	}
	p.set = set
	p.fetchedAt = time.Now()
	return p.set, nil
}

// SafeEngine is the endpoint-access SPOCP engine type. It is an alias for
// spocputil.Engine -- the same engine type pkg/issuance uses for
// credential-issuance policy rules -- so both rule sets are built,
// validated, and queried through one shared implementation instead of each
// package maintaining its own copy. Kept as a named alias (rather than
// updating every call site to spocputil.Engine) since *SafeEngine is
// threaded through handler signatures across internal/apigw and
// internal/verifier.
type SafeEngine = spocputil.Engine

// apiAuthRuleDimensions lists the tagged sub-lists of an SPOCP endpoint rule.
var apiAuthRuleDimensions = resourcereach.RuleDimensions()

// BuildSPOCPEngine creates a SPOCP engine from the APIAuth rules.
// Returns nil when no rules are configured (authentication-only mode).
func BuildSPOCPEngine(cfg model.APIAuth) (*SafeEngine, error) {
	return spocputil.BuildEngine("vc", apiAuthRuleDimensions, true, "SPOCP", cfg.Rules, cfg.RulesFile)
}

// extractSPOCPSubject returns the identity to use as the SPOCP subject
// from a validated JWT, preferring eppn → email
func extractSPOCPSubject(token jwt.Token) string {
	var s string
	if err := token.Get("eppn", &s); err == nil && s != "" {
		return s
	}
	if err := token.Get("email", &s); err == nil && s != "" {
		return s
	}
	return ""
}

// BuildSPOCPQuery constructs a SPOCP query S-expression over all six
// dimensions rules can match on: the service name, the HTTP method and path,
// the JWT subject, and the requested authentic_source and scope:
//
//	(vc (service apigw)(method POST)(path /api/v1/upload)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))
//
// The service dimension ensures that rules written for one service do not
// accidentally grant access to another service sharing the same endpoints.
func BuildSPOCPQuery(service, method, path, subject, authenticSource, scope string) sexp.Element {
	return spocputil.BuildTaggedQuery("vc", apiAuthRuleDimensions, map[string]string{
		"service":          service,
		"method":           method,
		"path":             path,
		"subject":          subject,
		"authentic_source": authenticSource,
		"scope":            scope,
	})
}

// authorizeTokenSubject binds the reach of a validated token's subject and, when
// rules are configured, runs the SPOCP check. A request naming no pair asks about
// the empty pair, which only a wildcard source and scope accept. A failure aborts
// the request and returns false.
func authorizeTokenSubject(c *gin.Context, engine *SafeEngine, service, subject string, log *logger.Log) bool {
	if engine != nil && subject == "" {
		log.Info("jwt_missing_identity", "error", "token has no eppn or email claim", "req_id", c.GetString("req_id"))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token missing eppn or email claim"})
		return false
	}
	if _, ok := bindResourceReach(c, engine, service, subject, log); !ok {
		return false
	}
	if engine == nil {
		return true
	}
	guard := resourceGuard{engine: engine, service: service, subject: subject, log: log}
	c.Set(resourceGuardKey, guard)
	pairs := extractResourcePairs(c)
	if len(pairs) == 0 {
		pairs = []resourcePair{{}}
	}
	if !guard.allows(c, pairs) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return false
	}
	return true
}

// JWKSAuth returns a Gin middleware that validates Bearer JWT tokens and
// optionally checks SPOCP authorization rules.
//
// The middleware extracts the token from the Authorization header, validates
// its signature against the JWKS at the configured URL, and verifies the
// standard "iss" and "aud" claims.
//
// When a SPOCP engine is provided (non-nil), the middleware additionally
// checks whether the request (method + path + subject) is authorized.
//
// On success the parsed claims are stored in the Gin context under the key
// "jwt_claims" and the subject identity (resolved from the "eppn" or "email"
// claim, not the standard "sub" claim) is stored under "jwt_subject".
func (m *middlewareHandler) JWKSAuth(ctx context.Context, service string, cfg model.APIAuthJWKS, jwksCache JWKSCache, engine *SafeEngine) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:JWKSAuth")
	defer span.End()

	log := m.log.New("jwks_auth")

	// Build a KeySetProvider based on the configured source.
	var keyProvider KeySetProvider
	switch {
	case cfg.JWKSFilePath != "":
		p, err := newFileKeySetProvider(cfg.JWKSFilePath)
		if err != nil {
			log.Error(err, "jwks_provider_init_failed", "source", "file")
			return func(c *gin.Context) {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "unable to validate token"})
			}
		}
		log.Info("jwks_provider_ready", "source", "file", "path", cfg.JWKSFilePath, "key_count", p.set.Len())
		keyProvider = p
	case cfg.JWKSURL != "":
		if jwksCache == nil {
			log.Error(nil, "jwks_cache_nil", "hint", "jwks_url requires a cache instance")
			return func(c *gin.Context) {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "JWKS authentication misconfigured"})
			}
		}
		p := newURLKeySetProvider(ctx, cfg.JWKSURL, jwksCache, func(msg string, args ...any) {
			log.Info(msg, args...)
		})
		if p.set != nil {
			log.Info("jwks_provider_ready", "source", "url", "url", cfg.JWKSURL, "key_count", p.set.Len())
		} else {
			log.Info("jwks_provider_deferred", "source", "url", "url", cfg.JWKSURL)
		}
		keyProvider = p
	default:
		log.Error(nil, "jwks_no_source_configured", "hint", "set jwks_url or jwks_file_path")
		return func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "JWKS authentication not configured"})
		}
	}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header, expected Bearer token"})
			return
		}
		tokenStr := parts[1]

		keys, err := keyProvider.GetKeySet(c.Request.Context())
		if err != nil {
			log.Error(err, "jwks_fetch_error")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service temporarily unavailable"})
			return
		}

		token, err := jwt.Parse(
			[]byte(tokenStr),
			jwt.WithKeySet(keys),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
		)
		if err != nil {
			log.Info("jwt_validation_failed", "error", err, "req_id", c.GetString("req_id"))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		sub := extractSPOCPSubject(token)
		if !authorizeTokenSubject(c, engine, service, sub, log) {
			return
		}

		c.Set("jwt_claims", token)
		c.Set("jwt_subject", sub)

		c.Next()
		log.Info("jwt_auth", "subject", sub, "req_id", c.GetString("req_id"))
	}
}

// JWKSAuthWithProvider is like JWKSAuth but accepts a pre-built KeySetProvider
// instead of constructing one from config. Used for OIDC discovery where the
// provider handles both discovery and JWKS fetching with retry logic.
func (m *middlewareHandler) JWKSAuthWithProvider(_ context.Context, service string, cfg model.APIAuthJWKS, keyProvider KeySetProvider, engine *SafeEngine) gin.HandlerFunc {
	log := m.log.New("jwks_auth")

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header, expected Bearer token"})
			return
		}
		tokenStr := parts[1]

		keys, err := keyProvider.GetKeySet(c.Request.Context())
		if err != nil {
			log.Error(err, "jwks_fetch_error")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service temporarily unavailable"})
			return
		}

		token, err := jwt.Parse(
			[]byte(tokenStr),
			jwt.WithKeySet(keys),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
		)
		if err != nil {
			log.Info("jwt_validation_failed", "error", err, "req_id", c.GetString("req_id"))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		sub := extractSPOCPSubject(token)
		if !authorizeTokenSubject(c, engine, service, sub, log) {
			return
		}

		c.Set("jwt_claims", token)
		c.Set("jwt_subject", sub)

		c.Next()
		log.Info("jwt_auth", "subject", sub, "req_id", c.GetString("req_id"))
	}
}

// APIAuth returns a Gin middleware that applies the authentication method
// configured in APIAuth:
//
//   - If JWKS.Enable is true – Bearer JWT authentication against a static JWKS URL
//   - If OIDC.Enable is true – Bearer JWT authentication via auto-discovered JWKS
//   - If neither is enabled  – no authentication (open access)
//
// JWKS and OIDC are mutually exclusive.
// SPOCP rules (if configured) apply to whichever mode is active.
//
// The service parameter identifies the logical service (e.g. "apigw", "issuer")
// and is included in SPOCP queries so that rules written for one service
// do not accidentally grant access to another.
func (m *middlewareHandler) APIAuth(ctx context.Context, service string, apiAuth model.APIAuth, jwksCache JWKSCache) (gin.HandlerFunc, error) {
	// Build SPOCP engine from top-level rules (applies to either auth mode).
	engine, err := BuildSPOCPEngine(apiAuth)
	if err != nil {
		return nil, fmt.Errorf("api_auth: failed to build SPOCP engine: %w", err)
	}

	switch {
	case apiAuth.JWKS.Enable:
		if apiAuth.JWKS.JWKSFilePath != "" {
			if engine != nil {
				m.log.Info("api_auth_mode", "mode", "jwks_file+spocp", "jwks_file_path", apiAuth.JWKS.JWKSFilePath, "rules", engine.RuleCount())
			} else {
				m.log.Info("api_auth_mode", "mode", "jwks_file", "jwks_file_path", apiAuth.JWKS.JWKSFilePath)
			}
		} else {
			if jwksCache == nil {
				return nil, fmt.Errorf("api_auth: jwks.enable is true but no JWKS cache was provided")
			}
			if engine != nil {
				m.log.Info("api_auth_mode", "mode", "jwks+spocp", "jwks_url", apiAuth.JWKS.JWKSURL, "rules", engine.RuleCount())
			} else {
				m.log.Info("api_auth_mode", "mode", "jwks", "jwks_url", apiAuth.JWKS.JWKSURL)
			}
		}
		return m.JWKSAuth(ctx, service, apiAuth.JWKS, jwksCache, engine), nil

	case apiAuth.OIDC.Enable:
		if jwksCache == nil {
			return nil, fmt.Errorf("api_auth: oidc.enable is true but no JWKS cache was provided")
		}
		if engine != nil {
			m.log.Info("api_auth_mode", "mode", "oidc+spocp", "issuer", apiAuth.OIDC.IssuerURL, "rules", engine.RuleCount())
		} else {
			m.log.Info("api_auth_mode", "mode", "oidc", "issuer", apiAuth.OIDC.IssuerURL)
		}
		oidcProvider := newOIDCKeySetProvider(ctx, apiAuth.OIDC.IssuerURL, jwksCache, func(msg string, args ...any) {
			m.log.Info(msg, args...)
		})
		oidcCfg := model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  "oidc-discovery://" + apiAuth.OIDC.IssuerURL, // placeholder, not actually fetched directly
			Issuer:   apiAuth.OIDC.IssuerURL,
			Audience: apiAuth.OIDC.Audience,
		}
		return m.JWKSAuthWithProvider(ctx, service, oidcCfg, oidcProvider, engine), nil

	default:
		m.log.Info("api_auth_mode", "mode", "none")
		return func(c *gin.Context) {
			c.Set(resourceReachKey, resourcereach.Everything())
			c.Next()
		}, nil
	}
}

// discoverJWKSURL fetches the OIDC discovery document and returns the jwks_uri.
func discoverJWKSURL(ctx context.Context, issuerURL string) (string, error) {
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("failed to decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document has no jwks_uri")
	}
	return doc.JWKSURI, nil
}
