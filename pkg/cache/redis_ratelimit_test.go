package cache

import (
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check.
var _ RateLimitCounter = (*RedisRateLimitCounter)(nil)

func TestRedisRateLimitCounter_NilClient(t *testing.T) {
	_, err := NewRedisRateLimitCounter(nil, "ratelimit_test", nil)
	assert.Error(t, err)
}

func TestRedisRateLimitCounter_EmptyPrefix(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	_, err := NewRedisRateLimitCounter(client, "", nil)
	assert.Error(t, err, "an empty prefix defeats the whole point of namespacing keys, so it must be rejected")
}

func TestRedisRateLimitCounter_FirstIncrement(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, "ratelimit_test", nil)
	require.NoError(t, err)

	count, err := rl.IncrementWithTTL(t.Context(), "test-key", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "first increment in a fresh window should report exactly 1")
}

func TestRedisRateLimitCounter_MultipleIncrementsInSameWindow(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, "ratelimit_test", nil)
	require.NoError(t, err)

	ctx := t.Context()
	var last int64
	for range 5 {
		count, err := rl.IncrementWithTTL(ctx, "test-key-multi", time.Minute)
		require.NoError(t, err)
		last = count
	}
	// All 5 calls land in the same current sub-window (no previous-window
	// contribution yet), so the final estimate must be exactly 5.
	assert.Equal(t, int64(5), last)
}

func TestRedisRateLimitCounter_IndependentKeys(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, "ratelimit_test", nil)
	require.NoError(t, err)

	ctx := t.Context()
	countA, err := rl.IncrementWithTTL(ctx, "key-a", time.Minute)
	require.NoError(t, err)
	countB, err := rl.IncrementWithTTL(ctx, "key-b", time.Minute)
	require.NoError(t, err)

	assert.Equal(t, int64(1), countA)
	assert.Equal(t, int64(1), countB, "a distinct key must not share the other key's window count")
}

// TestRedisRateLimitCounter_TTLSetOnFreshWindowKey confirms the underlying
// Redis key created by the first increment in a window actually carries a
// TTL (rather than living forever), matching MongoRateLimitCounter's
// TTL-indexed cleanup.
func TestRedisRateLimitCounter_TTLSetOnFreshWindowKey(t *testing.T) {
	testRateLimitTTLSetOnFreshWindowKey(t, startRedisContainer)
}

// testRateLimitTTLSetOnFreshWindowKey is shared by the Redis and Valkey
// variants above/below - the assertion is backend-agnostic, only the
// container differs.
func testRateLimitTTLSetOnFreshWindowKey(t *testing.T, startContainer func(*testing.T) (redis.UniversalClient, func())) {
	t.Helper()
	client, cleanup := startContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, "ratelimit_test", nil)
	require.NoError(t, err)

	ctx := t.Context()
	window := time.Minute
	// IncrementWithTTL computes its own windowID from an internal
	// time.Now(), taken after this call starts - bracket it with a
	// before/after pair and check both candidate window keys, since a
	// boundary crossed between "before" and that internal call would
	// otherwise make this look up a different (empty) key and fail
	// spuriously even though the real key got its TTL correctly.
	before := time.Now()
	_, err = rl.IncrementWithTTL(ctx, "ttl-check", window)
	require.NoError(t, err)
	after := time.Now()

	windowSecs := int64(window.Seconds())
	candidates := []int64{before.Unix() / windowSecs, after.Unix() / windowSecs}

	var ttl time.Duration
	for _, id := range candidates {
		key := "ratelimit_test:ttl-check:" + strconv.FormatInt(id, 10)
		v, err := client.TTL(ctx, key).Result()
		require.NoError(t, err)
		if v > ttl {
			ttl = v
		}
	}
	assert.Greater(t, ttl, time.Duration(0), "fresh window key must have a TTL set")
}

// --- RedisRateLimitCounter-against-Valkey tests (require Docker) ---
//
// IncrementWithTTL's correctness hinges on Valkey executing incrWithTTLScript
// (a Lua script run via EVAL) atomically, the same way Redis does. These
// tests confirm that against a real Valkey server.

func TestValkeyRateLimitCounter_FirstIncrement(t *testing.T) {
	client, cleanup := startValkeyContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, "ratelimit_test", nil)
	require.NoError(t, err)

	count, err := rl.IncrementWithTTL(t.Context(), "test-key", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "first increment in a fresh window should report exactly 1")
}

// TestValkeyRateLimitCounter_TTLSetOnFreshWindowKey mirrors
// TestRedisRateLimitCounter_TTLSetOnFreshWindowKey, confirming the Lua
// script's conditional EXPIRE call actually takes effect on Valkey.
func TestValkeyRateLimitCounter_TTLSetOnFreshWindowKey(t *testing.T) {
	testRateLimitTTLSetOnFreshWindowKey(t, startValkeyContainer)
}
