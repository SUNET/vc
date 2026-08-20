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
	_, err = rl.IncrementWithTTL(ctx, "ttl-check", window)
	require.NoError(t, err)

	currWindowID := time.Now().Unix() / int64(window.Seconds())
	key := "ttl-check:" + strconv.FormatInt(currWindowID, 10)
	ttl, err := client.TTL(ctx, key).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0), "fresh window key must have a TTL set")
}
