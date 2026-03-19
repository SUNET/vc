package trust

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	// DefaultTrustCacheTTL is the default TTL for trust decisions.
	// Trust decisions are relatively stable, so a longer TTL is appropriate.
	DefaultTrustCacheTTL = 5 * time.Minute

	// MaxTrustCacheTTL is the maximum TTL for trust decisions.
	MaxTrustCacheTTL = 1 * time.Hour
)

// TrustCache caches trust evaluation results to avoid repeated remote calls.
// It uses a composite key based on SubjectID, KeyType, Role, and key fingerprint.
type TrustCache struct {
	cache *ttlcache.Cache[string, *CachedDecision]
}

// CachedDecision wraps a TrustDecision with cache metadata.
type CachedDecision struct {
	Decision  *TrustDecision
	CachedAt  time.Time
	ExpiresAt time.Time
}

// TrustCacheConfig contains configuration for the trust cache.
type TrustCacheConfig struct {
	// TTL is the time-to-live for cached decisions. Default: 5 minutes.
	TTL time.Duration

	// MaxCapacity is the maximum number of items in the cache.
	// If 0, no capacity limit is applied (items only expire by TTL).
	MaxCapacity uint64
}

// NewTrustCache creates and starts a new trust decision cache.
func NewTrustCache(config TrustCacheConfig) *TrustCache {
	ttl := config.TTL
	if ttl <= 0 {
		ttl = DefaultTrustCacheTTL
	}
	if ttl > MaxTrustCacheTTL {
		ttl = MaxTrustCacheTTL
	}

	opts := []ttlcache.Option[string, *CachedDecision]{
		ttlcache.WithTTL[string, *CachedDecision](ttl),
	}

	if config.MaxCapacity > 0 {
		opts = append(opts, ttlcache.WithCapacity[string, *CachedDecision](config.MaxCapacity))
	}

	cache := ttlcache.New(opts...)

	// Start automatic expiration
	go cache.Start()

	return &TrustCache{
		cache: cache,
	}
}

// Get retrieves a cached trust decision for the given request.
// Returns nil if not found or expired.
func (c *TrustCache) Get(req *EvaluationRequest) *TrustDecision {
	key := c.buildCacheKey(req)
	item := c.cache.Get(key)
	if item == nil {
		return nil
	}

	cached := item.Value()
	if cached == nil {
		return nil
	}

	return cached.Decision
}

// Set stores a trust decision in the cache.
func (c *TrustCache) Set(req *EvaluationRequest, decision *TrustDecision) {
	c.SetWithTTL(req, decision, ttlcache.DefaultTTL)
}

// SetWithTTL stores a trust decision with a custom TTL.
func (c *TrustCache) SetWithTTL(req *EvaluationRequest, decision *TrustDecision, ttl time.Duration) {
	key := c.buildCacheKey(req)
	now := time.Now()

	cached := &CachedDecision{
		Decision:  decision,
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	c.cache.Set(key, cached, ttl)
}

// Invalidate removes a specific entry from the cache.
func (c *TrustCache) Invalidate(req *EvaluationRequest) {
	key := c.buildCacheKey(req)
	c.cache.Delete(key)
}

// InvalidateSubject removes all entries for a subject from the cache.
// This is useful when a subject's trust status is known to have changed.
func (c *TrustCache) InvalidateSubject(subjectID string) {
	// ttlcache doesn't support prefix deletion, so we use DeleteFunc
	c.cache.DeleteAll()
	// Note: This deletes everything. For production, consider using
	// a cache that supports prefix-based deletion or maintaining
	// a secondary index by subject.
}

// Clear removes all entries from the cache.
func (c *TrustCache) Clear() {
	c.cache.DeleteAll()
}

// Stop stops the cache's automatic expiration goroutine.
func (c *TrustCache) Stop() {
	c.cache.Stop()
}

// Len returns the number of items currently in the cache.
func (c *TrustCache) Len() int {
	return c.cache.Len()
}

// buildCacheKey creates a unique cache key from an evaluation request.
// The key includes: SubjectID, KeyType, Role/Action, CredentialType, DocType, and key fingerprint.
func (c *TrustCache) buildCacheKey(req *EvaluationRequest) string {
	h := sha256.New()

	// Include subject identifier
	h.Write([]byte(req.SubjectID))
	h.Write([]byte{0}) // separator

	// Include key type
	h.Write([]byte(req.KeyType))
	h.Write([]byte{0})

	// Include effective action (combines Role, Action, CredentialType)
	h.Write([]byte(req.GetEffectiveAction()))
	h.Write([]byte{0})

	// Include DocType for mDOC
	h.Write([]byte(req.DocType))
	h.Write([]byte{0})

	// Include key fingerprint
	keyFingerprint := computeKeyFingerprint(req.Key, req.KeyType)
	h.Write([]byte(keyFingerprint))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// computeKeyFingerprint generates a fingerprint for the key material.
// This ensures cache invalidation if the key changes.
func computeKeyFingerprint(key any, keyType KeyType) string {
	if key == nil {
		return ""
	}

	h := sha256.New()

	switch keyType {
	case KeyTypeX5C:
		// For x5c, hash the leaf certificate's raw bytes
		switch chain := key.(type) {
		case []*x509.Certificate:
			if len(chain) > 0 {
				h.Write(chain[0].Raw)
			}
		case X5CCertChain:
			if len(chain) > 0 {
				h.Write(chain[0].Raw)
			}
		}

	case KeyTypeJWK:
		// For JWK, serialize and hash
		switch jwk := key.(type) {
		case map[string]any:
			// Sort keys for consistent hashing
			data, err := json.Marshal(jwk)
			if err == nil {
				h.Write(data)
			}
		}

	default:
		// For other key types, try to get a string representation
		h.Write(fmt.Appendf(nil, "%v", key))
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16]) // Use first 16 bytes
}

// CachingTrustEvaluator wraps a TrustEvaluator with caching.
type CachingTrustEvaluator struct {
	evaluator TrustEvaluator
	cache     *TrustCache
}

// NewCachingTrustEvaluator creates a caching wrapper around a TrustEvaluator.
func NewCachingTrustEvaluator(evaluator TrustEvaluator, config TrustCacheConfig) *CachingTrustEvaluator {
	return &CachingTrustEvaluator{
		evaluator: evaluator,
		cache:     NewTrustCache(config),
	}
}

// Evaluate checks the cache first, then delegates to the wrapped evaluator.
func (c *CachingTrustEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	// Check for bypass cache option
	if req.Options != nil && req.Options.BypassCache {
		return c.evaluator.Evaluate(ctx, req)
	}

	// Check cache
	if cached := c.cache.Get(req); cached != nil {
		return cached, nil
	}

	// Evaluate
	decision, err := c.evaluator.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache successful decisions
	// Only cache positive decisions by default to avoid caching transient failures
	if decision != nil && decision.Trusted {
		c.cache.Set(req, decision)
	}

	return decision, nil
}

// SupportsKeyType delegates to the wrapped evaluator.
func (c *CachingTrustEvaluator) SupportsKeyType(kt KeyType) bool {
	return c.evaluator.SupportsKeyType(kt)
}

// Invalidate removes an entry from the cache.
func (c *CachingTrustEvaluator) Invalidate(req *EvaluationRequest) {
	c.cache.Invalidate(req)
}

// Clear removes all entries from the cache.
func (c *CachingTrustEvaluator) Clear() {
	c.cache.Clear()
}

// Stop stops the cache's automatic expiration.
func (c *CachingTrustEvaluator) Stop() {
	c.cache.Stop()
}

// Cache returns the underlying cache for advanced operations.
func (c *CachingTrustEvaluator) Cache() *TrustCache {
	return c.cache
}
