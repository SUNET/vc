// Package trust — JWKSKeyResolver implements SD-JWT VC spec §5.3 key resolution
// via JWT VC Issuer Metadata (.well-known/jwt-vc-issuer).
package trust

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
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

// JWKSKeyResolver resolves issuer public keys via JWT VC Issuer Metadata (SD-JWT VC §5.3).
//
// Resolution flow:
//  1. Fetch {issuer}/.well-known/jwt-vc-issuer → JWT VC Issuer Metadata
//  2. Validate metadata.issuer matches the expected issuer
//  3. Obtain JWKS from inline jwks field or follow jwks_uri
//  4. Cache the resolved JWKS per issuer URL
//  5. Match by kid to return the correct key
type JWKSKeyResolver struct {
	httpClient  *http.Client
	cache       *ttlcache.Cache[string, *cachedJWKS]
	parseJWK    func(jwkData any) (crypto.PublicKey, error)
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

	return &JWKSKeyResolver{
		httpClient: httpClient,
		cache:      cache,
		parseJWK:   config.ParseJWKToPublicKey,
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

// fetchIssuerJWKS fetches the JWT VC Issuer Metadata and resolves the JWKS.
func (r *JWKSKeyResolver) fetchIssuerJWKS(ctx context.Context, issuerURL string) (*cachedJWKS, error) {
	// Fetch JWT VC Issuer Metadata per SD-JWT VC §5.3
	metadataURL := strings.TrimRight(issuerURL, "/") + "/.well-known/jwt-vc-issuer"
	var metadata jwtVCIssuerMetadata
	if _, err := r.fetchJSON(ctx, metadataURL, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch JWT VC Issuer Metadata from %s: %w", metadataURL, err)
	}

	// Validate issuer match (security requirement per §5.3)
	if metadata.Issuer != issuerURL {
		return nil, fmt.Errorf("metadata issuer %q does not match expected issuer %q", metadata.Issuer, issuerURL)
	}

	// Get raw JWKS keys: inline or via jwks_uri
	var rawKeys []json.RawMessage
	if metadata.JWKS != nil && len(metadata.JWKS.Keys) > 0 {
		rawKeys = metadata.JWKS.Keys
	} else if metadata.JWKSURI != "" {
		var fetchErr error
		rawKeys, fetchErr = r.fetchJWKSKeys(ctx, metadata.JWKSURI)
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", metadata.JWKSURI, fetchErr)
		}
	} else {
		return nil, fmt.Errorf("issuer metadata contains neither jwks nor jwks_uri")
	}

	// Parse all keys
	entries := make([]jwkEntry, 0, len(rawKeys))
	for _, raw := range rawKeys {
		var jwkMap map[string]any
		if err := json.Unmarshal(raw, &jwkMap); err != nil {
			continue // skip unparseable keys
		}

		kid, _ := jwkMap["kid"].(string)

		publicKey, err := r.parseJWK(jwkMap)
		if err != nil {
			continue // skip keys that can't be parsed
		}

		entries = append(entries, jwkEntry{
			kid:       kid,
			jwkMap:    jwkMap,
			publicKey: publicKey,
		})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("issuer JWKS contains no usable keys")
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
