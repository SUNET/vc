// Package trust — JWKSKeyResolver implements SD-JWT VC spec §5.3 key resolution
// with a multi-endpoint discovery chain for maximum interoperability.
package trust

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	// DefaultJWKSCacheTTL is the default TTL for cached JWKS entries.
	DefaultJWKSCacheTTL = 5 * time.Minute

	// DefaultJWKSMaxCapacity is the default max capacity for the JWKS cache.
	DefaultJWKSMaxCapacity = 100
)

// JWKSResolverConfig contains configuration for the JWKSKeyResolver.
type JWKSResolverConfig struct {
	// HTTPClient is the HTTP client used for fetching metadata and JWKS.
	// If nil, a default client with 30s timeout is used.
	HTTPClient *http.Client

	// CacheTTL is the time-to-live for cached JWKS entries per issuer.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// MaxCapacity is the maximum number of issuers to cache.
	// Default: 100.
	MaxCapacity uint64

	// ParseJWKToPublicKey converts a JWK map to a crypto.PublicKey.
	// If nil, a default implementation using lestrrat-go/jwx is expected
	// to be injected by the caller (avoids coupling pkg/trust to pkg/jose).
	ParseJWKToPublicKey func(jwkData any) (crypto.PublicKey, error)
}

// JWKSKeyResolver resolves issuer public keys using a multi-endpoint discovery chain
// per SD-JWT VC §5.3 with fallbacks for maximum interoperability:
//
//  1. .well-known/jwt-vc-issuer → inline jwks or jwks_uri (SD-JWT VC §5.3 primary)
//  2. .well-known/openid-credential-issuer → authorization_servers → AS metadata → jwks_uri
//  3. .well-known/openid-configuration → jwks_uri (OIDC Discovery)
//  4. .well-known/oauth-authorization-server → jwks_uri (RFC 8414)
//
// Resolved JWKS are cached per issuer URL. Keys are matched by kid.
type JWKSKeyResolver struct {
	httpClient *http.Client
	cache      *ttlcache.Cache[string, *cachedJWKS]
	parseJWK   func(jwkData any) (crypto.PublicKey, error)
}

// cachedJWKS holds the parsed JWKS keys for an issuer.
type cachedJWKS struct {
	keys []jwkEntry
}

// jwkEntry holds a single JWK as both a map (for trust evaluation) and parsed public key.
type jwkEntry struct {
	kid       string
	jwkMap    map[string]any
	publicKey crypto.PublicKey
}

// jwtVCIssuerMetadata represents the JWT VC Issuer Metadata response per SD-JWT VC §5.3.
type jwtVCIssuerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri,omitempty"`
	JWKS    *struct {
		Keys []json.RawMessage `json:"keys"`
	} `json:"jwks,omitempty"`
}

// oidcDiscoveryMetadata represents fields we need from OIDC or OAuth AS metadata.
type oidcDiscoveryMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri,omitempty"`
}

// credentialIssuerMetadata represents fields we need from OID4VCI metadata.
type credentialIssuerMetadata struct {
	CredentialIssuer     string   `json:"credential_issuer"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
}

// NewJWKSKeyResolver creates a new resolver for SD-JWT VC issuer key resolution.
// The parseJWK function must be provided to convert JWK maps to crypto.PublicKey
// (this avoids coupling pkg/trust to pkg/jose).
func NewJWKSKeyResolver(config JWKSResolverConfig) *JWKSKeyResolver {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	cacheTTL := config.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultJWKSCacheTTL
	}

	maxCapacity := config.MaxCapacity
	if maxCapacity == 0 {
		maxCapacity = DefaultJWKSMaxCapacity
	}

	cache := ttlcache.New(
		ttlcache.WithTTL[string, *cachedJWKS](cacheTTL),
		ttlcache.WithCapacity[string, *cachedJWKS](maxCapacity),
	)
	go cache.Start()

	parseJWK := config.ParseJWKToPublicKey
	if parseJWK == nil {
		parseJWK = func(jwkData any) (crypto.PublicKey, error) {
			return nil, fmt.Errorf("ParseJWKToPublicKey not configured")
		}
	}

	return &JWKSKeyResolver{
		httpClient: httpClient,
		cache:      cache,
		parseJWK:   parseJWK,
	}
}

// ResolveKeyByKID resolves the public key for the given issuer and kid.
// Returns the public key and the JWK map (for trust evaluation).
//
// Per SD-JWT VC §5.3, the metadata is fetched from {issuer}/.well-known/jwt-vc-issuer.
// Resolved JWKS are cached per issuer URL.
func (r *JWKSKeyResolver) ResolveKeyByKID(ctx context.Context, issuerURL, kid string) (crypto.PublicKey, map[string]any, error) {
	if issuerURL == "" {
		return nil, nil, fmt.Errorf("issuer URL is empty")
	}
	if kid == "" {
		return nil, nil, fmt.Errorf("kid is empty")
	}

	// Check cache first
	jwks, err := r.getOrFetchJWKS(ctx, issuerURL)
	if err != nil {
		return nil, nil, err
	}

	// Find the key matching the kid
	for _, entry := range jwks.keys {
		if entry.kid == kid {
			return entry.publicKey, entry.jwkMap, nil
		}
	}

	// Fallback: if the JWKS has exactly one key, use it regardless of kid.
	// This handles the common case where the issuer generates the kid
	// differently (e.g. from certificate CN vs key thumbprint).
	if len(jwks.keys) == 1 {
		return jwks.keys[0].publicKey, jwks.keys[0].jwkMap, nil
	}

	return nil, nil, fmt.Errorf("no key found in issuer JWKS matching kid %q", kid)
}

// getOrFetchJWKS returns the cached JWKS for the issuer, or fetches and caches it.
func (r *JWKSKeyResolver) getOrFetchJWKS(ctx context.Context, issuerURL string) (*cachedJWKS, error) {
	// Check cache
	item := r.cache.Get(issuerURL)
	if item != nil {
		return item.Value(), nil
	}

	// Cache miss — fetch from issuer
	jwks, err := r.fetchIssuerJWKS(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	r.cache.Set(issuerURL, jwks, ttlcache.DefaultTTL)
	return jwks, nil
}

// fetchIssuerJWKS discovers and fetches the issuer's JWKS using the SD-JWT VC §5.3
// discovery chain with fallbacks:
//  1. .well-known/jwt-vc-issuer (SD-JWT VC primary)
//  2. .well-known/openid-credential-issuer → authorization_servers → OAuth AS metadata → jwks_uri
//  3. .well-known/openid-configuration → jwks_uri (OIDC Discovery)
//  4. .well-known/oauth-authorization-server → jwks_uri (RFC 8414)
func (r *JWKSKeyResolver) fetchIssuerJWKS(ctx context.Context, issuerURL string) (*cachedJWKS, error) {
	baseURL := strings.TrimRight(issuerURL, "/")
	var joinedErr error

	// 1. Try .well-known/jwt-vc-issuer (SD-JWT VC §5.3 primary)
	rawKeys, err := r.tryJWTVCIssuerMetadata(ctx, baseURL, issuerURL)
	if err == nil {
		return r.parseRawKeys(rawKeys)
	}
	joinedErr = errors.Join(joinedErr, fmt.Errorf("jwt-vc-issuer: %w", err))

	// 2. Try .well-known/openid-credential-issuer → chase AS metadata → jwks_uri
	rawKeys, err = r.tryCredentialIssuerMetadata(ctx, baseURL)
	if err == nil {
		return r.parseRawKeys(rawKeys)
	}
	joinedErr = errors.Join(joinedErr, fmt.Errorf("openid-credential-issuer: %w", err))

	// 3. Try .well-known/openid-configuration (OIDC Discovery) → jwks_uri
	rawKeys, err = r.tryOAuthMetadata(ctx, buildWellKnownURL(baseURL, "openid-configuration"), issuerURL)
	if err == nil {
		return r.parseRawKeys(rawKeys)
	}
	joinedErr = errors.Join(joinedErr, fmt.Errorf("openid-configuration: %w", err))

	// 4. Try .well-known/oauth-authorization-server (RFC 8414) → jwks_uri
	rawKeys, err = r.tryOAuthMetadata(ctx, buildWellKnownURL(baseURL, "oauth-authorization-server"), issuerURL)
	if err == nil {
		return r.parseRawKeys(rawKeys)
	}
	joinedErr = errors.Join(joinedErr, fmt.Errorf("oauth-authorization-server: %w", err))

	return nil, fmt.Errorf("failed to discover JWKS for issuer %s: %w", issuerURL, joinedErr)
}

// tryJWTVCIssuerMetadata tries the SD-JWT VC §5.3 primary discovery endpoint.
// The well-known URL is constructed per RFC 8615 §3: the well-known string is inserted
// between the host component and the path component of the issuer URL.
func (r *JWKSKeyResolver) tryJWTVCIssuerMetadata(ctx context.Context, baseURL, issuerURL string) ([]json.RawMessage, error) {
	metadataURL := buildWellKnownURL(baseURL, "jwt-vc-issuer")
	var metadata jwtVCIssuerMetadata
	if _, err := r.fetchJSON(ctx, metadataURL, &metadata); err != nil {
		return nil, err
	}

	if metadata.Issuer != issuerURL {
		return nil, fmt.Errorf("metadata issuer %q does not match expected %q", metadata.Issuer, issuerURL)
	}

	return r.extractJWKSFromMetadata(ctx, metadata.JWKS, metadata.JWKSURI)
}

// tryCredentialIssuerMetadata tries OID4VCI credential issuer metadata, then chases
// authorization_servers to find an OAuth AS with a jwks_uri.
func (r *JWKSKeyResolver) tryCredentialIssuerMetadata(ctx context.Context, baseURL string) ([]json.RawMessage, error) {
	var ciMeta credentialIssuerMetadata
	if _, err := r.fetchJSON(ctx, baseURL+"/.well-known/openid-credential-issuer", &ciMeta); err != nil {
		return nil, err
	}

	// Chase each authorization server's metadata for a jwks_uri
	asURLs := ciMeta.AuthorizationServers
	if len(asURLs) == 0 {
		// Default: the issuer itself is the authorization server
		asURLs = []string{baseURL}
	}

	for _, asURL := range asURLs {
		asBase := strings.TrimRight(asURL, "/")
		rawKeys, err := r.tryOAuthMetadata(ctx, buildWellKnownURL(asBase, "oauth-authorization-server"), asURL)
		if err == nil {
			return rawKeys, nil
		}
		rawKeys, err = r.tryOAuthMetadata(ctx, buildWellKnownURL(asBase, "openid-configuration"), asURL)
		if err == nil {
			return rawKeys, nil
		}
	}

	return nil, fmt.Errorf("no authorization server metadata with jwks_uri found")
}

// tryOAuthMetadata tries an OAuth/OIDC metadata endpoint and follows jwks_uri if present.
func (r *JWKSKeyResolver) tryOAuthMetadata(ctx context.Context, metadataURL, expectedIssuer string) ([]json.RawMessage, error) {
	var metadata oidcDiscoveryMetadata
	if _, err := r.fetchJSON(ctx, metadataURL, &metadata); err != nil {
		return nil, err
	}

	if metadata.Issuer != expectedIssuer {
		return nil, fmt.Errorf("metadata issuer %q does not match expected %q", metadata.Issuer, expectedIssuer)
	}

	if metadata.JWKSURI == "" {
		return nil, fmt.Errorf("metadata at %s has no jwks_uri", metadataURL)
	}

	return r.fetchJWKSKeys(ctx, metadata.JWKSURI)
}

// extractJWKSFromMetadata returns raw JWK keys from inline jwks or jwks_uri.
func (r *JWKSKeyResolver) extractJWKSFromMetadata(ctx context.Context, jwks *struct {
	Keys []json.RawMessage `json:"keys"`
}, jwksURI string,
) ([]json.RawMessage, error) {
	if jwks != nil && len(jwks.Keys) > 0 {
		return jwks.Keys, nil
	}
	if jwksURI != "" {
		return r.fetchJWKSKeys(ctx, jwksURI)
	}
	return nil, fmt.Errorf("metadata contains neither jwks nor jwks_uri")
}

// parseRawKeys parses raw JSON JWK entries into cached key entries.
func (r *JWKSKeyResolver) parseRawKeys(rawKeys []json.RawMessage) (*cachedJWKS, error) {
	if len(rawKeys) == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}

	entries := make([]jwkEntry, 0, len(rawKeys))
	var parseErr error
	for _, raw := range rawKeys {
		var jwkMap map[string]any
		if err := json.Unmarshal(raw, &jwkMap); err != nil {
			parseErr = errors.Join(parseErr, fmt.Errorf("failed to unmarshal JWK: %w", err))
			continue
		}

		kid, _ := jwkMap["kid"].(string)

		publicKey, err := r.parseJWK(jwkMap)
		if err != nil {
			parseErr = errors.Join(parseErr, fmt.Errorf("failed to parse JWK kid=%q: %w", kid, err))
			continue
		}

		entries = append(entries, jwkEntry{
			kid:       kid,
			jwkMap:    jwkMap,
			publicKey: publicKey,
		})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable keys: %w", parseErr)
	}

	return &cachedJWKS{keys: entries}, nil
}

// fetchJWKSKeys fetches a JWKS from a URI and returns the raw key entries.
func (r *JWKSKeyResolver) fetchJWKSKeys(ctx context.Context, jwksURI string) ([]json.RawMessage, error) {
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if _, err := r.fetchJSON(ctx, jwksURI, &jwks); err != nil {
		return nil, err
	}
	return jwks.Keys, nil
}

// fetchJSON fetches a URL and decodes the JSON response into the given target.
// Returns the decoded target and any error.
func (r *JWKSKeyResolver) fetchJSON(ctx context.Context, url string, target any) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return nil, fmt.Errorf("failed to decode response from %s: %w", url, err)
	}

	return target, nil
}

// buildWellKnownURL constructs a well-known URL per RFC 8615 §3.
// The well-known suffix is inserted between the host and path components of the entity URL.
// For example, with suffix "jwt-vc-issuer":
//
//	https://example.com           → https://example.com/.well-known/jwt-vc-issuer
//	https://example.com/tenant/1  → https://example.com/.well-known/jwt-vc-issuer/tenant/1
func buildWellKnownURL(entity, suffix string) string {
	entity = strings.TrimSuffix(entity, "/")

	parsed, err := url.Parse(entity)
	if err != nil || parsed.Host == "" {
		// Best-effort fallback: just append
		return entity + "/.well-known/" + suffix
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	base := parsed.Scheme + "://" + parsed.Host

	if path == "" {
		return base + "/.well-known/" + suffix
	}
	return base + "/.well-known/" + suffix + "/" + path
}

// Stop stops the cache's automatic expiration goroutine.
func (r *JWKSKeyResolver) Stop() {
	r.cache.Stop()
}

// InvalidateIssuer removes a cached JWKS for a specific issuer.
// Useful when key rotation is detected (e.g., kid not found in cached JWKS).
func (r *JWKSKeyResolver) InvalidateIssuer(issuerURL string) {
	r.cache.Delete(issuerURL)
}

// Len returns the number of issuers currently cached.
func (r *JWKSKeyResolver) Len() int {
	return r.cache.Len()
}
