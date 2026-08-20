package cache

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check.
var _ RateLimitCounter = (*RedisRateLimitCounter)(nil)

func TestRedisRateLimitCounter_NilClient(t *testing.T) {
	_, err := NewRedisRateLimitCounter(nil, nil)
	assert.Error(t, err)
}

func TestRedisRateLimitCounter_FirstIncrement(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, nil)
	require.NoError(t, err)

	count, err := rl.IncrementWithTTL(t.Context(), "test-key", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "first increment in a fresh window should report exactly 1")
}

func TestRedisRateLimitCounter_MultipleIncrementsInSameWindow(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, nil)
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

	rl, err := NewRedisRateLimitCounter(client, nil)
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
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	rl, err := NewRedisRateLimitCounter(client, nil)
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
		key := "ttl-check:" + strconv.FormatInt(id, 10)
		v, err := client.TTL(ctx, key).Result()
		require.NoError(t, err)
		if v > ttl {
			ttl = v
		}
	}
	assert.Greater(t, ttl, time.Duration(0), "fresh window key must have a TTL set")
}
