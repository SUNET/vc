package openid4vp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := t.Context()

	t.Run("with nil config uses default TTL", func(t *testing.T) {
		client, err := New(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		defer client.Close()

		// Verify ephemeral key cache is initialized
		assert.NotNil(t, client.EphemeralKeyCache)
		assert.Equal(t, 0, client.EphemeralKeyCache.Len())

		// Verify request object cache is initialized
		assert.NotNil(t, client.RequestObjectCache)
		assert.Equal(t, 0, client.RequestObjectCache.Len())
	})

	t.Run("with empty config uses default TTL", func(t *testing.T) {
		client, err := New(ctx, &Config{})
		require.NoError(t, err)
		require.NotNil(t, client)
		defer client.Close()

		assert.NotNil(t, client.EphemeralKeyCache)
		assert.Equal(t, 0, client.EphemeralKeyCache.Len())

		assert.NotNil(t, client.RequestObjectCache)
		assert.Equal(t, 0, client.RequestObjectCache.Len())
	})

	t.Run("with custom TTL", func(t *testing.T) {
		customKeyTTL := 5 * time.Minute
		customRequestTTL := 3 * time.Minute
		client, err := New(ctx, &Config{
			EphemeralKeyTTL:  customKeyTTL,
			RequestObjectTTL: customRequestTTL,
		})
		require.NoError(t, err)
		require.NotNil(t, client)
		defer client.Close()

		// Verify both caches are initialized
		assert.NotNil(t, client.EphemeralKeyCache)
		assert.Equal(t, 0, client.EphemeralKeyCache.Len())

		assert.NotNil(t, client.RequestObjectCache)
		assert.Equal(t, 0, client.RequestObjectCache.Len())
	})
}

func TestClient_EphemeralKeyCache(t *testing.T) {
	ctx := t.Context()
	client, err := New(ctx, nil)
	require.NoError(t, err)
	defer client.Close()

	cache := client.EphemeralKeyCache
	assert.NotNil(t, cache)
}

func TestClient_RequestObjectCache(t *testing.T) {
	ctx := t.Context()
	client, err := New(ctx, nil)
	require.NoError(t, err)
	defer client.Close()

	cache := client.RequestObjectCache
	assert.NotNil(t, cache)
}

func TestClient_Close(t *testing.T) {
	ctx := t.Context()
	client, err := New(ctx, nil)
	require.NoError(t, err)

	// Add a key to the ephemeral key cache
	key := createTestKey(t, "test-close-key")
	client.EphemeralKeyCache.Set("test-close-key", key)
	assert.Equal(t, 1, client.EphemeralKeyCache.Len())

	// Add a request object to the request object cache
	requestObject := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
	}
	client.RequestObjectCache.Set("urn:ietf:params:oauth:request_uri:test", requestObject)
	assert.Equal(t, 1, client.RequestObjectCache.Len())

	// Close should stop both caches
	client.Close()

	// Multiple closes should not panic
	client.Close()
}

func TestClient_EphemeralKeyCacheUsage(t *testing.T) {
	ctx := t.Context()
	client, err := New(ctx, nil)
	require.NoError(t, err)
	defer client.Close()

	// Test basic cache operations through client
	cache := client.EphemeralKeyCache

	// Set a key
	key1 := createTestKey(t, "client-key-1")
	cache.Set("client-key-1", key1)
	assert.Equal(t, 1, cache.Len())

	// Get the key back
	retrieved, found := cache.Get("client-key-1")
	assert.True(t, found)
	assert.NotNil(t, retrieved)

	// Set another key
	key2 := createTestKey(t, "client-key-2")
	cache.Set("client-key-2", key2)
	assert.Equal(t, 2, cache.Len())

	// Delete a key
	cache.Delete("client-key-1")
	assert.Equal(t, 1, cache.Len())

	// Verify only key2 remains
	_, found = cache.Get("client-key-1")
	assert.False(t, found)

	retrieved, found = cache.Get("client-key-2")
	assert.True(t, found)
	assert.NotNil(t, retrieved)
}

func TestClient_RequestObjectCacheUsage(t *testing.T) {
	ctx := t.Context()
	client, err := New(ctx, nil)
	require.NoError(t, err)
	defer client.Close()

	// Test basic cache operations through client
	cache := client.RequestObjectCache

	// Set a request object
	requestObject1 := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier1.example.com",
		Nonce:        "nonce-1",
	}
	requestURI1 := "urn:ietf:params:oauth:request_uri:test-1"
	cache.Set(requestURI1, requestObject1)
	assert.Equal(t, 1, cache.Len())

	// Get the request object back
	retrieved, found := cache.Get(requestURI1)
	assert.True(t, found)
	require.NotNil(t, retrieved)
	assert.Equal(t, requestObject1.ClientID, retrieved.ClientID)

	// Set another request object
	requestObject2 := &RequestObject{
		ResponseType: "vp_token id_token",
		ClientID:     "https://verifier2.example.com",
		Nonce:        "nonce-2",
	}
	requestURI2 := "urn:ietf:params:oauth:request_uri:test-2"
	cache.Set(requestURI2, requestObject2)
	assert.Equal(t, 2, cache.Len())

	// Delete a request object
	cache.Delete(requestURI1)
	assert.Equal(t, 1, cache.Len())

	// Verify only requestObject2 remains
	_, found = cache.Get(requestURI1)
	assert.False(t, found)

	retrieved, found = cache.Get(requestURI2)
	assert.True(t, found)
	require.NotNil(t, retrieved)
	assert.Equal(t, requestObject2.ClientID, retrieved.ClientID)
}
