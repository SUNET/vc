package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// startRedisContainer spins up a throwaway Redis via testcontainers and
// returns a connected redis.UniversalClient plus a cleanup function.
// Mirrors startMongoContainer's shape for this package's other backends.
func startRedisContainer(t *testing.T) (redis.UniversalClient, func()) {
	t.Helper()
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	container, err := tcredis.Run(ctx, "redis:7")
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("redis connection string: %v", err)
	}

	opts, err := redis.ParseURL(connStr)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("parse redis url: %v", err)
	}
	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		_ = container.Terminate(context.Background())
		t.Fatalf("ping redis: %v", err)
	}

	cleanup := func() {
		_ = client.Close()
		_ = container.Terminate(context.Background())
	}
	return client, cleanup
}

// Redis compile-time checks
var (
	_ Cache[string]     = (*RedisCache[string])(nil)
	_ Cache[bool]       = (*RedisCache[bool])(nil)
	_ Cache[int]        = (*RedisCache[int])(nil)
	_ Cache[testStruct] = (*RedisCache[testStruct])(nil)
)

// --- RedisCache tests (require Docker) ---

func TestRedisCache_String(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	c, err := NewRedisCache[string](client, "cache_string", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, "hello", "world")
}

func TestRedisCache_Bool(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	c, err := NewRedisCache[bool](client, "cache_bool", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, true, false)
}

func TestRedisCache_Int(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	c, err := NewRedisCache[int](client, "cache_int", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, 42, 99)
}

func TestRedisCache_Struct(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	c, err := NewRedisCache[testStruct](client, "cache_struct", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(
		t, c,
		testStruct{Name: "alice", Value: 1},
		testStruct{Name: "bob", Value: 2},
	)
}

func TestRedisCache_Bytes(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[[]byte](client, "cache_bytes", 10*time.Minute, nil)
	require.NoError(t, err)

	c.Set(ctx, "bin", []byte{0x01, 0x02})
	got, ok := c.Get(ctx, "bin")
	require.True(t, ok)
	assert.Equal(t, []byte{0x01, 0x02}, got)

	c.Delete(ctx, "bin")
	_, ok = c.Get(ctx, "bin")
	assert.False(t, ok)
}

func TestRedisCache_NilClient(t *testing.T) {
	_, err := NewRedisCache[string](nil, "col", 5*time.Minute, nil)
	assert.Error(t, err)
}

func TestRedisCache_JWKKey(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[jwk.Key](client, "cache_jwk", 10*time.Minute, nil, WithRedisDecoder(func(data []byte) (jwk.Key, error) {
		return jwk.ParseKey(data)
	}))
	require.NoError(t, err)

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(raw)
	require.NoError(t, err)

	c.Set(ctx, "k1", key)
	got, ok := c.Get(ctx, "k1")
	require.True(t, ok, "expected jwk.Key to round-trip through RedisCache")

	origJSON, err := json.Marshal(key)
	require.NoError(t, err)
	gotJSON, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, string(origJSON), string(gotJSON))
}

// TestRedisCache_KeysNamespacedByCollection confirms two RedisCache
// instances sharing one Redis client/keyspace don't collide, even when
// given the same user-facing key.
func TestRedisCache_KeysNamespacedByCollection(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	a, err := NewRedisCache[string](client, "cache_a", 10*time.Minute, nil)
	require.NoError(t, err)
	b, err := NewRedisCache[string](client, "cache_b", 10*time.Minute, nil)
	require.NoError(t, err)

	a.Set(ctx, "shared-key", "from-a")
	b.Set(ctx, "shared-key", "from-b")

	gotA, ok := a.Get(ctx, "shared-key")
	require.True(t, ok)
	assert.Equal(t, "from-a", gotA)

	gotB, ok := b.Get(ctx, "shared-key")
	require.True(t, ok)
	assert.Equal(t, "from-b", gotB)
}

// TestRedisCache_TTLExpiration confirms Redis's native per-key TTL (not
// MongoCache's created_at-shift approximation) actually expires entries.
func TestRedisCache_TTLExpiration(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[string](client, "cache_ttl", 200*time.Millisecond, nil)
	require.NoError(t, err)

	c.Set(ctx, "expiring", "value")
	_, ok := c.Get(ctx, "expiring")
	require.True(t, ok, "value should be present immediately after Set")

	time.Sleep(400 * time.Millisecond)
	_, ok = c.Get(ctx, "expiring")
	assert.False(t, ok, "value should have expired")
}
