package cache

import (
	"context"
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
	return startRedisCompatibleContainer(t, "redis:7")
}

// startValkeyContainer spins up a throwaway Valkey (the open-source Redis
// fork maintained under the Linux Foundation) via the same testcontainers
// module used for Redis. Valkey speaks the same RESP protocol and exposes
// the same port/startup log line Redis does, so no dedicated
// testcontainers module is needed - only the image differs. Its tests
// exist to prove RedisCache/RedisRateLimitCounter genuinely work against
// Valkey, not just Redis, since nothing else in this package would catch
// a protocol divergence.
func startValkeyContainer(t *testing.T) (redis.UniversalClient, func()) {
	t.Helper()
	return startRedisCompatibleContainer(t, "valkey/valkey:8")
}

// startRedisCompatibleContainer spins up img (any RESP-protocol server
// exposing the standard Redis port 6379) via testcontainers and returns a
// connected redis.UniversalClient plus a cleanup function.
func startRedisCompatibleContainer(t *testing.T, img string) (redis.UniversalClient, func()) {
	t.Helper()
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	container, err := tcredis.Run(ctx, img)
	if err != nil {
		t.Fatalf("start %s container: %v", img, err)
	}

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("%s connection string: %v", img, err)
	}

	opts, err := redis.ParseURL(connStr)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("parse %s url: %v", img, err)
	}
	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		_ = container.Terminate(context.Background())
		t.Fatalf("ping %s: %v", img, err)
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

func TestRedisCache_EmptyCollection(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	_, err := NewRedisCache[string](client, "", 5*time.Minute, nil)
	assert.Error(t, err, "an empty collection breaks key namespacing and widens Len()'s scan pattern, so it must be rejected")
}

func TestRedisCache_JWKKey(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[jwk.Key](client, "cache_jwk", 10*time.Minute, nil, WithRedisDecoder(func(data []byte) (jwk.Key, error) {
		return jwk.ParseKey(data)
	}))
	require.NoError(t, err)

	key := newTestECJWKKey(t)

	c.Set(ctx, "k1", key)
	got, ok := c.Get(ctx, "k1")
	require.True(t, ok, "expected jwk.Key to round-trip through RedisCache")

	assertSameJWKKey(t, key, got)
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

// TestRedisCache_SetWithTTL_NonPositiveExpiresImmediately confirms a
// non-positive TTL doesn't cache permanently (Redis's own SET treats
// ttl<=0 as "no expiration"), matching MongoCache.SetWithTTL(ttl<=0)'s
// effectively-immediate expiry.
func TestRedisCache_SetWithTTL_NonPositiveExpiresImmediately(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[string](client, "cache_ttl_nonpositive", 10*time.Minute, nil)
	require.NoError(t, err)

	c.SetWithTTL(ctx, "zero-ttl", "value", 0)
	time.Sleep(50 * time.Millisecond)
	_, ok := c.Get(ctx, "zero-ttl")
	assert.False(t, ok, "a zero TTL must not cache the value permanently")

	c.SetWithTTL(ctx, "negative-ttl", "value", -time.Second)
	time.Sleep(50 * time.Millisecond)
	_, ok = c.Get(ctx, "negative-ttl")
	assert.False(t, ok, "a negative TTL must not cache the value permanently")
}

// TestRedisCache_SetNX_NonPositiveDefaultTTLExpiresImmediately confirms
// SetNX() - which passes the cache's own default ttl straight through -
// doesn't create a permanent key when that default ttl is non-positive,
// matching setWithTTL's clamp.
func TestRedisCache_SetNX_NonPositiveDefaultTTLExpiresImmediately(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewRedisCache[string](client, "cache_setnx_nonpositive", 0, nil)
	require.NoError(t, err)

	ok, err := c.SetNX(ctx, "zero-default-ttl", "value")
	require.NoError(t, err)
	require.True(t, ok, "key didn't exist yet, so SetNX must report it was set")

	time.Sleep(50 * time.Millisecond)
	_, ok = c.Get(ctx, "zero-default-ttl")
	assert.False(t, ok, "SetNX must not cache the value permanently when the cache's default ttl is non-positive")
}

// --- RedisCache-against-Valkey tests (require Docker) ---
//
// RedisCache talks to its backend only through redis.UniversalClient's
// RESP commands (GET/SET/DEL/GETDEL/SCAN/SETNX+EX), with no
// Redis-specific behavior beyond that protocol surface. These tests run
// the same contract/TTL assertions used above against a real Valkey
// server to confirm that's actually true, rather than assuming
// wire-compatibility from Valkey's project description.

func TestValkeyCache_String(t *testing.T) {
	client, cleanup := startValkeyContainer(t)
	defer cleanup()

	c, err := NewRedisCache[string](client, "cache_string", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, "hello", "world")
}

// TestValkeyCache_TTLExpiration confirms Valkey actually expires keys via
// native per-key EXPIRE, matching TestRedisCache_TTLExpiration.
func TestValkeyCache_TTLExpiration(t *testing.T) {
	client, cleanup := startValkeyContainer(t)
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
