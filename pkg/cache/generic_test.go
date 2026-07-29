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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// runGenericCacheContractTests runs the shared contract tests that every
// Cache[V] implementation must satisfy. Reused for both memory and mongo.
func runGenericCacheContractTests[V comparable](t *testing.T, c Cache[V], val1, val2 V) {
	t.Helper()
	ctx := context.Background()

	t.Run("SetAndGet", func(t *testing.T) {
		c.Set(ctx, "key1", val1)
		got, ok := c.Get(ctx, "key1")
		require.True(t, ok)
		assert.Equal(t, val1, got)
	})

	t.Run("GetMissing", func(t *testing.T) {
		_, ok := c.Get(ctx, "nonexistent")
		assert.False(t, ok)
	})

	t.Run("SetOverwrite", func(t *testing.T) {
		c.Set(ctx, "key1", val2)
		got, ok := c.Get(ctx, "key1")
		require.True(t, ok)
		assert.Equal(t, val2, got)
	})

	t.Run("Delete", func(t *testing.T) {
		c.Set(ctx, "key-del", val1)
		c.Delete(ctx, "key-del")
		_, ok := c.Get(ctx, "key-del")
		assert.False(t, ok)
	})

	t.Run("DeleteMissing", func(t *testing.T) {
		// Should not panic or error
		c.Delete(ctx, "no-such-key")
	})

	t.Run("SetWithTTL", func(t *testing.T) {
		c.SetWithTTL(ctx, "key-ttl", val1, 1*time.Hour)
		got, ok := c.Get(ctx, "key-ttl")
		require.True(t, ok)
		assert.Equal(t, val1, got)
	})

	t.Run("GetAndDeleteHit", func(t *testing.T) {
		c.Set(ctx, "key-gad", val1)
		got, ok := c.GetAndDelete(ctx, "key-gad")
		require.True(t, ok)
		assert.Equal(t, val1, got)
		// Value must be removed after GetAndDelete
		_, ok = c.Get(ctx, "key-gad")
		assert.False(t, ok, "key should be removed after GetAndDelete")
	})

	t.Run("GetAndDeleteMiss", func(t *testing.T) {
		_, ok := c.GetAndDelete(ctx, "no-such-key-gad")
		assert.False(t, ok)
	})

	t.Run("Len", func(t *testing.T) {
		fresh := c.Len()
		assert.GreaterOrEqual(t, fresh, 0)
	})

	t.Run("SetNX_New", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "nx-new", val1)
		require.NoError(t, err)
		assert.True(t, ok, "SetNX on a new key should succeed")
		got, found := c.Get(ctx, "nx-new")
		require.True(t, found)
		assert.Equal(t, val1, got)
	})

	t.Run("SetNX_Existing", func(t *testing.T) {
		c.Set(ctx, "nx-exist", val1)
		ok, err := c.SetNX(ctx, "nx-exist", val2)
		require.NoError(t, err)
		assert.False(t, ok, "SetNX on existing key should return false")
		got, found := c.Get(ctx, "nx-exist")
		require.True(t, found)
		assert.Equal(t, val1, got, "value should not be overwritten")
	})

	t.Run("SetNXWithTTL_New", func(t *testing.T) {
		ok, err := c.SetNXWithTTL(ctx, "nxttl-new", val1, 1*time.Hour)
		require.NoError(t, err)
		assert.True(t, ok, "SetNXWithTTL on a new key should succeed")
		got, found := c.Get(ctx, "nxttl-new")
		require.True(t, found)
		assert.Equal(t, val1, got)
	})

	t.Run("SetNXWithTTL_Existing", func(t *testing.T) {
		c.Set(ctx, "nxttl-exist", val1)
		ok, err := c.SetNXWithTTL(ctx, "nxttl-exist", val2, 1*time.Hour)
		require.NoError(t, err)
		assert.False(t, ok, "SetNXWithTTL on existing key should return false")
		got, found := c.Get(ctx, "nxttl-exist")
		require.True(t, found)
		assert.Equal(t, val1, got, "value should not be overwritten")
	})

	t.Run("SetNXWithTTL_ZeroTTL_FallsBackToDefault", func(t *testing.T) {
		ok, err := c.SetNXWithTTL(ctx, "nxttl-zero", val1, 0)
		require.NoError(t, err)
		assert.True(t, ok, "SetNXWithTTL with zero TTL should succeed on new key")
		got, found := c.Get(ctx, "nxttl-zero")
		require.True(t, found)
		assert.Equal(t, val1, got)
	})

	t.Run("SetNXWithTTL_NegativeTTL_FallsBackToDefault", func(t *testing.T) {
		ok, err := c.SetNXWithTTL(ctx, "nxttl-neg", val1, -5*time.Second)
		require.NoError(t, err)
		assert.True(t, ok, "SetNXWithTTL with negative TTL should succeed on new key")
		got, found := c.Get(ctx, "nxttl-neg")
		require.True(t, found)
		assert.Equal(t, val1, got)
	})
}

// --- MemoryCache type-specific tests ---

func TestMemoryCache_String(t *testing.T) {
	c := NewMemoryCache[string](5 * time.Minute)
	runGenericCacheContractTests(t, c, "hello", "world")
}

func TestMemoryCache_Bool(t *testing.T) {
	c := NewMemoryCache[bool](5 * time.Minute)
	runGenericCacheContractTests(t, c, true, false)
}

func TestMemoryCache_Bytes(t *testing.T) {
	// []byte is not comparable, so test manually
	ctx := context.Background()
	c := NewMemoryCache[[]byte](5 * time.Minute)

	c.Set(ctx, "bin", []byte{0x01, 0x02})
	got, ok := c.Get(ctx, "bin")
	require.True(t, ok)
	assert.Equal(t, []byte{0x01, 0x02}, got)

	c.Delete(ctx, "bin")
	_, ok = c.Get(ctx, "bin")
	assert.False(t, ok)
}

func TestMemoryCache_Int(t *testing.T) {
	c := NewMemoryCache[int](5 * time.Minute)
	runGenericCacheContractTests(t, c, 42, 99)
}

type testStruct struct {
	Name  string `json:"name" bson:"name"`
	Value int    `json:"value" bson:"value"`
}

func TestMemoryCache_Struct(t *testing.T) {
	c := NewMemoryCache[testStruct](5 * time.Minute)
	runGenericCacheContractTests(
		t, c,
		testStruct{Name: "alice", Value: 1},
		testStruct{Name: "bob", Value: 2},
	)
}

func TestMemoryCache_StructPtr(t *testing.T) {
	c := NewMemoryCache[*testStruct](5 * time.Minute)
	runGenericCacheContractTests(
		t, c,
		&testStruct{Name: "alice", Value: 1},
		&testStruct{Name: "bob", Value: 2},
	)
}

func TestMemoryCache_TTLExpiration(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache[string](50 * time.Millisecond)

	c.Set(ctx, "expire-me", "value")
	time.Sleep(150 * time.Millisecond)

	_, ok := c.Get(ctx, "expire-me")
	assert.False(t, ok, "expected item to expire")
}

func TestMemoryCache_SetNXWithTTL_Expiration(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache[string](5 * time.Minute)

	// Store with a short custom TTL.
	ok, err := c.SetNXWithTTL(ctx, "nx-expire", "val", 50*time.Millisecond)
	require.NoError(t, err)
	require.True(t, ok)

	// Value should be readable immediately.
	got, found := c.Get(ctx, "nx-expire")
	require.True(t, found)
	assert.Equal(t, "val", got)

	// After the custom TTL elapses, the value should be gone.
	time.Sleep(150 * time.Millisecond)
	_, found = c.Get(ctx, "nx-expire")
	assert.False(t, found, "expected item to expire after custom TTL")
}

func TestMemoryCache_SetNXWithTTL_ZeroTTL_UsesDefault(t *testing.T) {
	ctx := context.Background()
	// Default TTL = 50ms. Zero TTL should fall back to default, not infinite.
	c := NewMemoryCache[string](50 * time.Millisecond)

	ok, err := c.SetNXWithTTL(ctx, "nx-zero-ttl", "val", 0)
	require.NoError(t, err)
	require.True(t, ok)

	// Value should be readable immediately.
	_, found := c.Get(ctx, "nx-zero-ttl")
	require.True(t, found)

	// After default TTL elapses, value should expire.
	time.Sleep(150 * time.Millisecond)
	_, found = c.Get(ctx, "nx-zero-ttl")
	assert.False(t, found, "zero TTL should fall back to default TTL, not infinite")
}

func TestMemoryCache_Stop(t *testing.T) {
	c := NewMemoryCache[string](5 * time.Minute)
	c.Stop() // should not panic
}

// --- Compile-time interface checks ---

var (
	_ Cache[string]      = (*MemoryCache[string])(nil)
	_ Cache[bool]        = (*MemoryCache[bool])(nil)
	_ Cache[int]         = (*MemoryCache[int])(nil)
	_ Cache[[]byte]      = (*MemoryCache[[]byte])(nil)
	_ Cache[testStruct]  = (*MemoryCache[testStruct])(nil)
	_ Cache[*testStruct] = (*MemoryCache[*testStruct])(nil)
)

// Mongo compile-time checks
var (
	_ Cache[string]     = (*MongoCache[string])(nil)
	_ Cache[bool]       = (*MongoCache[bool])(nil)
	_ Cache[int]        = (*MongoCache[int])(nil)
	_ Cache[testStruct] = (*MongoCache[testStruct])(nil)
)

// --- MongoCache tests (require Docker) ---

func TestMongoCache_String(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[string](t.Context(), client, "test_generic", "cache_string", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, "hello", "world")
}

func TestMongoCache_Bool(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[bool](t.Context(), client, "test_generic", "cache_bool", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, true, false)
}

func TestMongoCache_Int(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[int](t.Context(), client, "test_generic", "cache_int", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, 42, 99)
}

func TestMongoCache_Struct(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[testStruct](t.Context(), client, "test_generic", "cache_struct", 10*time.Minute, nil)
	require.NoError(t, err)
	runGenericCacheContractTests(
		t, c,
		testStruct{Name: "alice", Value: 1},
		testStruct{Name: "bob", Value: 2},
	)
}

func TestMongoCache_Bytes(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewMongoCache[[]byte](ctx, client, "test_generic", "cache_bytes", 10*time.Minute, nil)
	require.NoError(t, err)

	c.Set(ctx, "bin", []byte{0x01, 0x02})
	got, ok := c.Get(ctx, "bin")
	require.True(t, ok)
	assert.Equal(t, []byte{0x01, 0x02}, got)

	c.Delete(ctx, "bin")
	_, ok = c.Get(ctx, "bin")
	assert.False(t, ok)
}

func TestMongoCache_NilClient(t *testing.T) {
	_, err := NewMongoCache[string](context.Background(), nil, "db", "col", 5*time.Minute, nil)
	assert.Error(t, err)
}

func TestMongoCache_JWKKey(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewMongoCache[jwk.Key](ctx, client, "test_generic", "cache_jwk", 10*time.Minute, nil, WithDecoder(func(data []byte) (jwk.Key, error) {
		return jwk.ParseKey(data)
	}))
	require.NoError(t, err)

	// Generate a fresh EC key
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(raw)
	require.NoError(t, err)

	c.Set(ctx, "k1", key)
	got, ok := c.Get(ctx, "k1")
	require.True(t, ok, "expected jwk.Key to round-trip through MongoCache")

	// Verify the key material survived by comparing JSON serializations
	origJSON, err := json.Marshal(key)
	require.NoError(t, err)
	gotJSON, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, string(origJSON), string(gotJSON))
}

func TestMongoCache_SetWithTTL_ShorterThanDefault(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	// Collection TTL = 10 minutes.
	c, err := NewMongoCache[string](ctx, client, "test_generic", "cache_ttl_short", 10*time.Minute, nil)
	require.NoError(t, err)

	// Store with a 2-minute TTL. created_at should be shifted 8 minutes into the past.
	c.SetWithTTL(ctx, "short", "val", 2*time.Minute)

	// Read the raw document to verify the created_at shift.
	coll := client.Database("test_generic").Collection("cache_ttl_short")
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "short"}).Decode(&doc)
	require.NoError(t, err)

	createdAt := doc["created_at"].(bson.DateTime).Time()
	age := time.Since(createdAt)
	// created_at should be ~8 minutes in the past (shift = 10m - 2m).
	assert.InDelta(t, 8*time.Minute, age, float64(5*time.Second),
		"created_at should be shifted ~8 minutes into the past")

	// Value should still be readable.
	got, ok := c.Get(ctx, "short")
	require.True(t, ok)
	assert.Equal(t, "val", got)
}

func TestMongoCache_SetWithTTL_LongerThanDefault(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	// Collection TTL = 5 minutes.
	c, err := NewMongoCache[string](ctx, client, "test_generic", "cache_ttl_long", 5*time.Minute, nil)
	require.NoError(t, err)

	// Store with a 15-minute TTL. created_at should be shifted 10 minutes into the future.
	c.SetWithTTL(ctx, "long", "val", 15*time.Minute)

	coll := client.Database("test_generic").Collection("cache_ttl_long")
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "long"}).Decode(&doc)
	require.NoError(t, err)

	createdAt := doc["created_at"].(bson.DateTime).Time()
	offset := time.Until(createdAt)
	// created_at should be ~10 minutes in the future (shift = 5m - 15m = -10m).
	assert.InDelta(t, 10*time.Minute, offset, float64(5*time.Second),
		"created_at should be shifted ~10 minutes into the future")
}

func TestMongoCache_SetWithTTL_SameAsDefault(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewMongoCache[string](ctx, client, "test_generic", "cache_ttl_same", 10*time.Minute, nil)
	require.NoError(t, err)

	c.SetWithTTL(ctx, "same", "val", 10*time.Minute)

	coll := client.Database("test_generic").Collection("cache_ttl_same")
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "same"}).Decode(&doc)
	require.NoError(t, err)

	createdAt := doc["created_at"].(bson.DateTime).Time()
	age := time.Since(createdAt)
	// No shift; created_at should be ~now.
	assert.InDelta(t, 0, age, float64(5*time.Second),
		"created_at should be approximately now when TTL equals default")
}

func TestMongoCache_SetNXWithTTL_CreatedAtShift(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	// Collection TTL = 10 minutes.
	c, err := NewMongoCache[string](ctx, client, "test_generic", "cache_nxttl_shift", 10*time.Minute, nil)
	require.NoError(t, err)

	// SetNXWithTTL with 3-minute TTL should shift created_at 7 minutes into the past.
	ok, err := c.SetNXWithTTL(ctx, "nx-shift", "val", 3*time.Minute)
	require.NoError(t, err)
	require.True(t, ok)

	coll := client.Database("test_generic").Collection("cache_nxttl_shift")
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "nx-shift"}).Decode(&doc)
	require.NoError(t, err)

	createdAt := doc["created_at"].(bson.DateTime).Time()
	age := time.Since(createdAt)
	assert.InDelta(t, 7*time.Minute, age, float64(5*time.Second),
		"created_at should be shifted ~7 minutes into the past for 3-minute TTL")

	// Value should still be readable.
	got, found := c.Get(ctx, "nx-shift")
	require.True(t, found)
	assert.Equal(t, "val", got)
}

func TestMongoCache_SetNXWithTTL_ZeroTTL_NoShift(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewMongoCache[string](ctx, client, "test_generic", "cache_nxttl_zero", 10*time.Minute, nil)
	require.NoError(t, err)

	// Zero TTL should fall back to SetNX (default TTL), meaning created_at ~now.
	ok, err := c.SetNXWithTTL(ctx, "nx-zero", "val", 0)
	require.NoError(t, err)
	require.True(t, ok)

	coll := client.Database("test_generic").Collection("cache_nxttl_zero")
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "nx-zero"}).Decode(&doc)
	require.NoError(t, err)

	createdAt := doc["created_at"].(bson.DateTime).Time()
	age := time.Since(createdAt)
	assert.InDelta(t, 0, age, float64(5*time.Second),
		"zero TTL should fall back to default (created_at ~now)")
}
