package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("Len", func(t *testing.T) {
		fresh := c.Len()
		assert.GreaterOrEqual(t, fresh, 0)
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
	runGenericCacheContractTests(t, c,
		testStruct{Name: "alice", Value: 1},
		testStruct{Name: "bob", Value: 2},
	)
}

func TestMemoryCache_StructPtr(t *testing.T) {
	c := NewMemoryCache[*testStruct](5 * time.Minute)
	runGenericCacheContractTests(t, c,
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

func TestMemoryCache_Stop(t *testing.T) {
	c := NewMemoryCache[string](5 * time.Minute)
	c.Stop() // should not panic
}

// --- Compile-time interface checks ---

var _ Cache[string] = (*MemoryCache[string])(nil)
var _ Cache[bool] = (*MemoryCache[bool])(nil)
var _ Cache[int] = (*MemoryCache[int])(nil)
var _ Cache[[]byte] = (*MemoryCache[[]byte])(nil)
var _ Cache[testStruct] = (*MemoryCache[testStruct])(nil)
var _ Cache[*testStruct] = (*MemoryCache[*testStruct])(nil)

// Mongo compile-time checks
var _ Cache[string] = (*MongoCache[string])(nil)
var _ Cache[bool] = (*MongoCache[bool])(nil)
var _ Cache[int] = (*MongoCache[int])(nil)
var _ Cache[testStruct] = (*MongoCache[testStruct])(nil)

// --- MongoCache tests (require Docker) ---

func TestMongoCache_String(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[string](t.Context(), client, "test_generic", "cache_string", 10*time.Minute)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, "hello", "world")
}

func TestMongoCache_Bool(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[bool](t.Context(), client, "test_generic", "cache_bool", 10*time.Minute)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, true, false)
}

func TestMongoCache_Int(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[int](t.Context(), client, "test_generic", "cache_int", 10*time.Minute)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c, 42, 99)
}

func TestMongoCache_Struct(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	c, err := NewMongoCache[testStruct](t.Context(), client, "test_generic", "cache_struct", 10*time.Minute)
	require.NoError(t, err)
	runGenericCacheContractTests(t, c,
		testStruct{Name: "alice", Value: 1},
		testStruct{Name: "bob", Value: 2},
	)
}

func TestMongoCache_Bytes(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	ctx := t.Context()
	c, err := NewMongoCache[[]byte](ctx, client, "test_generic", "cache_bytes", 10*time.Minute)
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
	_, err := NewMongoCache[string](context.Background(), nil, "db", "col", 5*time.Minute)
	assert.Error(t, err)
}


