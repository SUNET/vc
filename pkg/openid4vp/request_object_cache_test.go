package openid4vp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequestObjectCache(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	require.NotNil(t, cache)
	defer cache.Stop()

	// Verify cache is empty initially
	assert.Equal(t, 0, cache.Len())
}

func TestRequestObjectCache_SetAndGet(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	requestURI := "urn:ietf:params:oauth:request_uri:test-123"
	requestObject := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
		Nonce:        "nonce-123",
	}

	// Set the request object
	cache.Set(requestURI, requestObject)
	assert.Equal(t, 1, cache.Len())

	// Get the request object back
	retrieved, found := cache.Get(requestURI)
	assert.True(t, found)
	require.NotNil(t, retrieved)
	assert.Equal(t, requestObject.ResponseType, retrieved.ResponseType)
	assert.Equal(t, requestObject.ClientID, retrieved.ClientID)
	assert.Equal(t, requestObject.Nonce, retrieved.Nonce)
}

func TestRequestObjectCache_GetNonExistent(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	// Try to get a non-existent request object
	retrieved, found := cache.Get("urn:ietf:params:oauth:request_uri:nonexistent")
	assert.False(t, found)
	assert.Nil(t, retrieved)
}

func TestRequestObjectCache_Delete(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	requestURI := "urn:ietf:params:oauth:request_uri:delete-test"
	requestObject := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
	}

	// Set and verify
	cache.Set(requestURI, requestObject)
	assert.Equal(t, 1, cache.Len())

	// Delete and verify
	cache.Delete(requestURI)
	assert.Equal(t, 0, cache.Len())

	// Verify it's gone
	_, found := cache.Get(requestURI)
	assert.False(t, found)
}

func TestRequestObjectCache_SetWithTTL(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	requestURI := "urn:ietf:params:oauth:request_uri:ttl-test"
	requestObject := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
	}

	// Set with a very short TTL
	cache.SetWithTTL(requestURI, requestObject, 100*time.Millisecond)
	assert.Equal(t, 1, cache.Len())

	// Should exist immediately
	_, found := cache.Get(requestURI)
	assert.True(t, found)

	// Wait for TTL to expire
	time.Sleep(200 * time.Millisecond)

	// Should be gone
	_, found = cache.Get(requestURI)
	assert.False(t, found)
	assert.Equal(t, 0, cache.Len())
}

func TestRequestObjectCache_MultipleRequestObjects(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	// Add multiple request objects
	for i := range 5 {
		requestURI := "urn:ietf:params:oauth:request_uri:test-" + string(rune('0'+i))
		requestObject := &RequestObject{
			ResponseType: "vp_token",
			ClientID:     "https://verifier.example.com",
			Nonce:        "nonce-" + string(rune('0'+i)),
		}
		cache.Set(requestURI, requestObject)
	}

	assert.Equal(t, 5, cache.Len())

	// Verify all are retrievable
	for i := range 5 {
		requestURI := "urn:ietf:params:oauth:request_uri:test-" + string(rune('0'+i))
		retrieved, found := cache.Get(requestURI)
		assert.True(t, found)
		require.NotNil(t, retrieved)
		assert.Equal(t, "nonce-"+string(rune('0'+i)), retrieved.Nonce)
	}
}

func TestRequestObjectCache_Overwrite(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	requestURI := "urn:ietf:params:oauth:request_uri:overwrite-test"

	// Set first request object
	requestObject1 := &RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier1.example.com",
		Nonce:        "nonce-1",
	}
	cache.Set(requestURI, requestObject1)

	// Overwrite with second request object
	requestObject2 := &RequestObject{
		ResponseType: "vp_token id_token",
		ClientID:     "https://verifier2.example.com",
		Nonce:        "nonce-2",
	}
	cache.Set(requestURI, requestObject2)

	// Should still have only 1 item
	assert.Equal(t, 1, cache.Len())

	// Should have the second request object
	retrieved, found := cache.Get(requestURI)
	assert.True(t, found)
	require.NotNil(t, retrieved)
	assert.Equal(t, requestObject2.ClientID, retrieved.ClientID)
	assert.Equal(t, requestObject2.Nonce, retrieved.Nonce)
}

func TestRequestObjectCache_ConcurrentAccess(t *testing.T) {
	cache := NewRequestObjectCache(5 * time.Minute)
	defer cache.Stop()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent writes
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestURI := "urn:ietf:params:oauth:request_uri:concurrent-" + string(rune('0'+id))
			requestObject := &RequestObject{
				ResponseType: "vp_token",
				ClientID:     "https://verifier.example.com",
				Nonce:        "nonce-" + string(rune('0'+id)),
			}
			cache.Set(requestURI, requestObject)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numGoroutines, cache.Len())

	// Concurrent reads
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			requestURI := "urn:ietf:params:oauth:request_uri:concurrent-" + string(rune('0'+id))
			retrieved, found := cache.Get(requestURI)
			assert.True(t, found)
			assert.NotNil(t, retrieved)
		}(i)
	}

	wg.Wait()
}
