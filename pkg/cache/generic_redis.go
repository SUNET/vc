package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// logPrefix prefixes every RedisCache log message so the backend is
// identifiable in shared logs alongside MongoCache/MemoryCache.
const logPrefix = "redis cache "

// RedisCache is a generic cache backed by Redis. Values are JSON-encoded
// before storage (matching MongoCache's approach), which allows interface
// types (e.g. jwk.Key) to round-trip correctly via a custom decoder. Unlike
// MongoCache, which approximates per-entry TTL by shifting created_at under
// a collection-wide TTL index, Redis has native per-key expiration (EXPIRE),
// so every TTL here is exact, not approximated.
//
// Keys are namespaced by collection ("<collection>:<key>") so multiple
// caches can safely share one Redis database/keyspace.
type RedisCache[V any] struct {
	client     redis.UniversalClient
	collection string
	ttl        time.Duration // default TTL for Set/SetNX
	log        Logger
	decode     func([]byte) (V, error) // optional custom JSON decoder
}

// RedisCacheOption configures optional behaviour for RedisCache.
type RedisCacheOption[V any] func(*RedisCache[V])

// WithRedisDecoder supplies a custom JSON decoder for V - use this for
// interface types (e.g. jwk.Key) where json.Unmarshal cannot infer the
// concrete type. Mirrors generic_mongo.go's WithDecoder.
func WithRedisDecoder[V any](fn func([]byte) (V, error)) RedisCacheOption[V] {
	return func(r *RedisCache[V]) { r.decode = fn }
}

// NewRedisCache creates a new Redis-backed generic cache. client may be a
// *redis.Client (single node) or *redis.ClusterClient (cluster mode) - both
// satisfy redis.UniversalClient, so callers can switch topology without any
// change here. If log is nil, operational errors are silently discarded.
func NewRedisCache[V any](client redis.UniversalClient, collection string, ttl time.Duration, log Logger, opts ...RedisCacheOption[V]) (*RedisCache[V], error) {
	if client == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}
	if log == nil {
		log = nopLogger{}
	}

	r := &RedisCache[V]{
		client:     client,
		collection: collection,
		ttl:        ttl,
		log:        log,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// namespacedKey prefixes key with this cache's collection so distinct
// RedisCache instances sharing one Redis database/keyspace never collide.
func (r *RedisCache[V]) namespacedKey(key string) string {
	return r.collection + ":" + key
}

// decodeValue unmarshals JSON bytes into V using the configured decoder.
func (r *RedisCache[V]) decodeValue(data []byte, op, key string) (V, bool) {
	var v V
	var err error
	if r.decode != nil {
		v, err = r.decode(data)
	} else {
		err = json.Unmarshal(data, &v)
	}
	if err != nil {
		r.log.Error(
			err, logPrefix+op+": failed to unmarshal JSON value",
			"cache", r.collection, "key", key,
		)
		var zero V
		return zero, false
	}
	return v, true
}

// Get retrieves a value by key.
func (r *RedisCache[V]) Get(ctx context.Context, key string) (V, bool) {
	data, err := r.client.Get(ctx, r.namespacedKey(key)).Bytes()
	if err != nil {
		var zero V
		if errors.Is(err, redis.Nil) {
			return zero, false
		}
		r.log.Error(err, "redis cache get: operational error treated as miss", "cache", r.collection, "key", key)
		return zero, false
	}
	return r.decodeValue(data, "get", key)
}

// Set stores a value with the default TTL configured at creation time.
func (r *RedisCache[V]) Set(ctx context.Context, key string, value V) {
	r.setWithTTL(ctx, key, value, r.ttl, "set")
}

// SetWithTTL stores a value with a custom TTL, overriding the default.
func (r *RedisCache[V]) SetWithTTL(ctx context.Context, key string, value V, ttl time.Duration) {
	r.setWithTTL(ctx, key, value, ttl, "setwithttl")
}

func (r *RedisCache[V]) setWithTTL(ctx context.Context, key string, value V, ttl time.Duration, op string) {
	// Redis's SET treats a non-positive expiration as "no expiration" -
	// the opposite of MongoCache's SetWithTTL(ttl<=0), which shifts
	// created_at so far into the past that the document is already
	// expired under the collection's TTL index. Clamp to the smallest
	// representable TTL instead, so a non-positive ttl still expires
	// (near-)immediately here too, rather than caching permanently.
	if ttl <= 0 {
		ttl = time.Millisecond
	}

	data, err := json.Marshal(value)
	if err != nil {
		r.log.Error(err, logPrefix+op+" marshal failed", "cache", r.collection, "key", key)
		return
	}
	if err := r.client.Set(ctx, r.namespacedKey(key), data, ttl).Err(); err != nil {
		r.log.Error(err, logPrefix+op+" failed", "cache", r.collection, "key", key)
	}
}

// SetNX stores a value only if the key does not already exist (atomic).
// Returns true if the value was set, false if the key already existed.
func (r *RedisCache[V]) SetNX(ctx context.Context, key string, value V) (bool, error) {
	return r.setNXWithTTL(ctx, key, value, r.ttl)
}

// SetNXWithTTL stores a value only if the key does not already exist
// (atomic), using a custom TTL instead of the default.
// If ttl <= 0, falls back to SetNX (default TTL).
func (r *RedisCache[V]) SetNXWithTTL(ctx context.Context, key string, value V, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return r.SetNX(ctx, key, value)
	}
	return r.setNXWithTTL(ctx, key, value, ttl)
}

func (r *RedisCache[V]) setNXWithTTL(ctx context.Context, key string, value V, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("redis cache setnx marshal failed (cache=%s): %w", r.collection, err)
	}
	// SET key value NX EX ttl is a single atomic Redis command - no
	// insert-and-catch-duplicate-key dance needed (unlike MongoCache's
	// SetNX, which relies on a unique index and a duplicate-key error).
	ok, err := r.client.SetNX(ctx, r.namespacedKey(key), data, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis cache setnx failed (cache=%s): %w", r.collection, err)
	}
	return ok, nil
}

// Delete removes a value by key.
func (r *RedisCache[V]) Delete(ctx context.Context, key string) {
	if err := r.client.Del(ctx, r.namespacedKey(key)).Err(); err != nil {
		r.log.Error(err, "redis cache delete failed", "cache", r.collection, "key", key)
	}
}

// GetAndDelete atomically retrieves and removes a value by key.
func (r *RedisCache[V]) GetAndDelete(ctx context.Context, key string) (V, bool) {
	// GETDEL is a single atomic Redis command (Redis 6.2+), unlike
	// MongoCache's FindOneAndDelete equivalent, which needs no such
	// version caveat on the Mongo side.
	data, err := r.client.GetDel(ctx, r.namespacedKey(key)).Bytes()
	if err != nil {
		var zero V
		if errors.Is(err, redis.Nil) {
			return zero, false
		}
		r.log.Error(err, "redis cache get-and-delete: operational error treated as miss", "cache", r.collection, "key", key)
		return zero, false
	}
	return r.decodeValue(data, "get-and-delete", key)
}

// Len returns the number of items currently in this cache. Implemented via
// SCAN (not KEYS, which blocks the server on large keyspaces) with a
// MATCH pattern scoped to this cache's collection prefix - an O(n) walk
// over this cache's own keys, not the whole Redis keyspace. Like
// MongoCache.Len (EstimatedDocumentCount), this is an approximate,
// informational count, not a value to build correctness on.
//
// On a *redis.ClusterClient, a single SCAN only walks the node it's sent
// to, not the whole cluster - keys live on whichever shard they hash to.
// Fan out via ForEachMaster and sum, so this stays a whole-cache count
// under either topology.
func (r *RedisCache[V]) Len() int {
	ctx := context.Background()
	pattern := r.collection + ":*"

	if cc, ok := r.client.(*redis.ClusterClient); ok {
		var total atomic.Int64
		if err := cc.ForEachMaster(ctx, func(ctx context.Context, master *redis.Client) error {
			n, err := scanCount(ctx, master, pattern)
			total.Add(int64(n))
			return err
		}); err != nil {
			r.log.Error(err, "redis cache len failed", "cache", r.collection)
		}
		return int(total.Load())
	}

	n, err := scanCount(ctx, r.client, pattern)
	if err != nil {
		r.log.Error(err, "redis cache len failed", "cache", r.collection)
	}
	return n
}

// scanCount counts keys matching pattern on a single node via SCAN.
func scanCount(ctx context.Context, client redis.UniversalClient, pattern string) (int, error) {
	var count int
	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return count, err
		}
		count += len(keys)
		cursor = next
		if cursor == 0 {
			return count, nil
		}
	}
}
