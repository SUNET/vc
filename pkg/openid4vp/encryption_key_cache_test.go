package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a test JWK key
func createTestKey(t *testing.T, kid string) jwk.Key {
	t.Helper()

	// Generate EC P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert to JWK
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Set key ID
	err = key.Set(jwk.KeyIDKey, kid)
	require.NoError(t, err)

	return key
}

func TestNewEphemeralEncryptionKeyCache(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(10 * time.Minute)
	assert.NotNil(t, cache)
	assert.NotNil(t, cache.cache)
	defer cache.Stop()

	// Verify cache is empty initially
	assert.Equal(t, 0, cache.Len())
}

func TestEphemeralEncryptionKeyCache_SetAndGet(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Generate a test key
	key := createTestKey(t, "test-kid-1")

	// Set the key
	cache.Set("test-kid-1", key)

	// Verify it was stored
	assert.Equal(t, 1, cache.Len())

	// Get the key back
	retrieved, found := cache.Get("test-kid-1")
	assert.True(t, found)
	assert.NotNil(t, retrieved)

	// Verify key ID matches
	kid, ok := retrieved.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "test-kid-1", kid)
}

func TestEphemeralEncryptionKeyCache_GetNonExistent(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Try to get a non-existent key
	key, found := cache.Get("non-existent-kid")
	assert.False(t, found)
	assert.Nil(t, key)
}

func TestEphemeralEncryptionKeyCache_Delete(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Generate and set a test key
	key := createTestKey(t, "test-kid-delete")

	cache.Set("test-kid-delete", key)
	assert.Equal(t, 1, cache.Len())

	// Delete the key
	cache.Delete("test-kid-delete")
	assert.Equal(t, 0, cache.Len())

	// Verify it's gone
	_, found := cache.Get("test-kid-delete")
	assert.False(t, found)
}

func TestEphemeralEncryptionKeyCache_SetWithTTL(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Generate a test key
	key := createTestKey(t, "test-kid-ttl")

	// Set with short TTL
	cache.SetWithTTL("test-kid-ttl", key, 100*time.Millisecond)

	// Verify it exists immediately
	_, found := cache.Get("test-kid-ttl")
	assert.True(t, found)

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Verify it's expired
	_, found = cache.Get("test-kid-ttl")
	assert.False(t, found)
}

func TestEphemeralEncryptionKeyCache_MultipleKeys(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Create multiple keys
	for i := 1; i <= 5; i++ {
		kid := "test-kid-" + string(rune('0'+i))
		key := createTestKey(t, kid)
		cache.Set(kid, key)
	}

	// Verify all keys are stored
	assert.Equal(t, 5, cache.Len())

	// Verify each key can be retrieved
	for i := 1; i <= 5; i++ {
		kid := "test-kid-" + string(rune('0'+i))
		retrieved, found := cache.Get(kid)
		assert.True(t, found, "key %s should be found", kid)
		assert.NotNil(t, retrieved)

		retrievedKid, ok := retrieved.KeyID()
		assert.True(t, ok)
		assert.Equal(t, kid, retrievedKid)
	}
}

func TestEphemeralEncryptionKeyCache_Overwrite(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Set initial key
	key1 := createTestKey(t, "overwrite-kid")
	cache.Set("overwrite-kid", key1)

	// Overwrite with new key
	key2 := createTestKey(t, "overwrite-kid")
	cache.Set("overwrite-kid", key2)

	// Should still have only 1 key
	assert.Equal(t, 1, cache.Len())

	// Retrieved key should exist
	retrieved, found := cache.Get("overwrite-kid")
	assert.True(t, found)
	assert.NotNil(t, retrieved)

	kid, ok := retrieved.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "overwrite-kid", kid)
}

func TestEphemeralEncryptionKeyCache_ConcurrentAccess(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(1 * time.Hour)
	defer cache.Stop()

	// Test concurrent writes and reads
	done := make(chan bool)

	// Writer goroutines
	for i := range 10 {
		go func(id int) {
			kid := "concurrent-key-" + string(rune('0'+id))
			key := createTestKey(t, kid)
			cache.Set(kid, key)
			done <- true
		}(i)
	}

	// Wait for all writes
	for range 10 {
		<-done
	}

	// Verify all keys were stored
	assert.Equal(t, 10, cache.Len())

	// Reader goroutines
	for i := range 10 {
		go func(id int) {
			kid := "concurrent-key-" + string(rune('0'+id))
			retrieved, found := cache.Get(kid)
			assert.True(t, found)
			assert.NotNil(t, retrieved)
			done <- true
		}(i)
	}

	// Wait for all reads
	for range 10 {
		<-done
	}
}

func TestEphemeralEncryptionKeyCache_GenerateAndStore(t *testing.T) {
	cache := NewEphemeralEncryptionKeyCache(5 * time.Minute)
	defer cache.Stop()

	kid := "test-generated-key"

	// Generate and store key pair
	privateKey, publicKey, err := cache.GenerateAndStore(kid)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotNil(t, publicKey)

	// Verify private key is in cache
	assert.Equal(t, 1, cache.Len())
	retrieved, found := cache.Get(kid)
	assert.True(t, found)
	require.NotNil(t, retrieved)

	// Verify KID is set on both keys
	privateKid, ok := privateKey.KeyID()
	assert.True(t, ok)
	assert.Equal(t, kid, privateKid)

	publicKid, ok := publicKey.KeyID()
	assert.True(t, ok)
	assert.Equal(t, kid, publicKid)

	// Verify public key has "use" set to "enc"
	use, ok := publicKey.KeyUsage()
	assert.True(t, ok)
	assert.Equal(t, "enc", use)

	// Verify key type is EC
	assert.Equal(t, "EC", privateKey.KeyType().String())
	assert.Equal(t, "EC", publicKey.KeyType().String())
}
