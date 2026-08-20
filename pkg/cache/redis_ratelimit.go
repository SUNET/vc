package cache

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrWithTTLScript atomically increments a counter and, only on the
// increment that creates the key (count==1), sets its TTL - as a single
// Lua script, so there's no window between INCR and EXPIRE where a crash
// could leave the key permanently un-expiring. Redis executes scripts
// atomically, so this replaces INCR + a conditional, separate EXPIRE call.
var incrWithTTLScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
`)

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

	// Atomically increment and, only on the increment that creates the key,
	// set its TTL - covers current + previous window, matching
	// MongoRateLimitCounter's 120s TTL index for its default ~60s window.
	// Derived from the normalized windowSecs (not the raw window param) so
	// a zero/negative/sub-second window - which falls back to the 60s
	// default above - gets a TTL consistent with that same 60s bucketing.
	ttlSecs := 2 * windowSecs
	currCount, err := incrWithTTLScript.Run(ctx, r.client, []string{currKey}, ttlSecs).Int64()
	if err != nil {
		return 0, fmt.Errorf("rate limit increment failed (key=%s): %w", currKey, err)
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
