package cache

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// MemoryCache is a generic in-memory cache backed by ttlcache.
// Suitable for single-instance deployments. For HA, swap with MongoCache.
type MemoryCache[V any] struct {
	cache *ttlcache.Cache[string, V]
}

// NewMemoryCache creates a new in-memory generic cache with the given default TTL.
func NewMemoryCache[V any](ttl time.Duration) *MemoryCache[V] {
	c := ttlcache.New(
		ttlcache.WithTTL[string, V](ttl),
	)

	go c.Start()

	return &MemoryCache[V]{cache: c}
}

// Get retrieves a value by key.
func (m *MemoryCache[V]) Get(_ context.Context, key string) (V, bool) {
	item := m.cache.Get(key)
	if item == nil {
		var zero V
		return zero, false
	}
	return item.Value(), true
}

// Set stores a value with the default TTL.
func (m *MemoryCache[V]) Set(_ context.Context, key string, value V) {
	m.cache.Set(key, value, ttlcache.DefaultTTL)
}

// SetNX stores a value only if the key does not already exist.
// Returns true if the value was set, false if the key already existed.
func (m *MemoryCache[V]) SetNX(_ context.Context, key string, value V) (bool, error) {
	_, found := m.cache.GetOrSet(key, value)
	return !found, nil
}

// SetWithTTL stores a value with a custom TTL.
func (m *MemoryCache[V]) SetWithTTL(_ context.Context, key string, value V, ttl time.Duration) {
	m.cache.Set(key, value, ttl)
}

// Delete removes a value by key.
func (m *MemoryCache[V]) Delete(_ context.Context, key string) {
	m.cache.Delete(key)
}

// Len returns the number of items currently in the cache.
func (m *MemoryCache[V]) Len() int {
	return m.cache.Len()
}

// Stop stops the background expiration goroutine.
func (m *MemoryCache[V]) Stop() {
	m.cache.Stop()
}
