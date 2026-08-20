package cache

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimitCounter is a Redis-backed sliding-window rate limit counter.
// It mirrors MongoRateLimitCounter's algorithm exactly (two fixed
// sub-windows per key, weighted to approximate a sliding window), but the
// current sub-window's counter is incremented via Redis's native atomic
// INCR rather than a MongoDB FindOneAndUpdate upsert - the "insert or
// update" case Mongo needs an upsert for is simply INCR's normal behavior
// on a nonexistent key.
type RedisRateLimitCounter struct {
	client redis.UniversalClient
	log    Logger
}

// NewRedisRateLimitCounter creates a new Redis-backed rate limit counter.
func NewRedisRateLimitCounter(client redis.UniversalClient, log Logger) (*RedisRateLimitCounter, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}
	if log == nil {
		log = nopLogger{}
	}
	return &RedisRateLimitCounter{client: client, log: log}, nil
}

// IncrementWithTTL atomically increments the current sub-window's counter
// and returns the sliding-window estimate.
func (r *RedisRateLimitCounter) IncrementWithTTL(ctx context.Context, key string, window time.Duration) (int64, error) {
	now := time.Now()
	windowSecs := int64(window.Seconds())
	if windowSecs <= 0 {
		windowSecs = 60
	}
	currWindowID := now.Unix() / windowSecs
	prevWindowID := currWindowID - 1

	currKey := fmt.Sprintf("%s:%d", key, currWindowID)
	prevKey := fmt.Sprintf("%s:%d", key, prevWindowID)

	// INCR atomically creates currKey at 1 (if absent) or increments it.
	// Since INCR is atomic, exactly one caller ever observes the return
	// value 1 for a given key even under concurrent access - that caller,
	// and only that caller, sets the TTL, so a fresh key can't end up
	// without one (a raced double-EXPIRE would be harmless anyway; this
	// just avoids resetting the TTL on every increment).
	currCount, err := r.client.Incr(ctx, currKey).Result()
	if err != nil {
		return 0, fmt.Errorf("rate limit increment failed (key=%s): %w", currKey, err)
	}
	if currCount == 1 {
		// Covers current + previous window, matching MongoRateLimitCounter's
		// 120s TTL index for its default ~60s window. Derived from the
		// normalized windowSecs (not the raw window param) so a zero/
		// negative/sub-second window - which falls back to the 60s default
		// above - gets a TTL consistent with that same 60s bucketing,
		// instead of a mismatched (or zero/negative, which Redis treats as
		// "delete immediately") duration from the raw window.
		ttl := 2 * time.Duration(windowSecs) * time.Second
		if err := r.client.Expire(ctx, currKey, ttl).Err(); err != nil {
			r.log.Error(err, "rate limit: failed to set TTL on fresh window key", "key", currKey)
		}
	}

	// Read the previous window's count (read-only - already finalized).
	var prevCount int64
	prevVal, err := r.client.Get(ctx, prevKey).Int64()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return 0, fmt.Errorf("rate limit prev read failed (key=%s): %w", prevKey, err)
		}
	} else {
		prevCount = prevVal
	}

	// Sliding window estimate.
	elapsedInWindow := now.Unix() % windowSecs
	prevWeight := 1.0 - float64(elapsedInWindow)/float64(windowSecs)
	estimate := int64(math.Ceil(float64(prevCount)*prevWeight)) + currCount

	return estimate, nil
}
