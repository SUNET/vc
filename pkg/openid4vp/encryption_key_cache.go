package openid4vp

import (
	"crypto/ecdh"
	"crypto/rand"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	// DefaultEphemeralKeyTTL is the default TTL for ephemeral encryption keys
	DefaultEphemeralKeyTTL = 10 * time.Minute
)

// EphemeralEncryptionKeyCache manages short-lived encryption keys for response encryption
type EphemeralEncryptionKeyCache struct {
	cache *ttlcache.Cache[string, jwk.Key]
}

// NewEphemeralEncryptionKeyCache creates and starts a new ephemeral encryption key cache
// with the specified TTL. Keys are automatically evicted after the TTL expires.
func NewEphemeralEncryptionKeyCache(ttl time.Duration) *EphemeralEncryptionKeyCache {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, jwk.Key](ttl),
	)

	// Start automatic expiration
	go cache.Start()

	return &EphemeralEncryptionKeyCache{
		cache: cache,
	}
}

// Get retrieves an ephemeral encryption key by its key ID (kid)
func (e *EphemeralEncryptionKeyCache) Get(kid string) (jwk.Key, bool) {
	item := e.cache.Get(kid)
	if item == nil {
		return nil, false
	}
	return item.Value(), true
}

// Set stores an ephemeral encryption key with the specified key ID (kid)
func (e *EphemeralEncryptionKeyCache) Set(kid string, key jwk.Key) {
	e.cache.Set(kid, key, ttlcache.DefaultTTL)
}

// SetWithTTL stores an ephemeral encryption key with a custom TTL
func (e *EphemeralEncryptionKeyCache) SetWithTTL(kid string, key jwk.Key, ttl time.Duration) {
	e.cache.Set(kid, key, ttl)
}

// Delete removes an ephemeral encryption key from the cache
func (e *EphemeralEncryptionKeyCache) Delete(kid string) {
	e.cache.Delete(kid)
}

// Stop stops the cache's automatic expiration goroutine
func (e *EphemeralEncryptionKeyCache) Stop() {
	e.cache.Stop()
}

// Len returns the number of items currently in the cache
func (e *EphemeralEncryptionKeyCache) Len() int {
	return e.cache.Len()
}

// GenerateAndStore generates a new ephemeral encryption key pair, stores the private key in the cache,
// and returns both private and public JWKs. The key uses ECDH P-256.
func (e *EphemeralEncryptionKeyCache) GenerateAndStore(kid string) (privateKey jwk.Key, publicKey jwk.Key, err error) {
	// Generate ECDH P-256 key pair
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Convert private key to JWK
	privateJWK, err := jwk.Import(privKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}

	// Store private key in cache
	e.Set(kid, privateJWK)

	// Get public key
	pub := privKey.Public()

	// Convert public key to JWK
	publicJWK, err := jwk.Import(pub)
	if err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set(jwk.KeyUsageKey, "enc"); err != nil {
		return nil, nil, err
	}

	// alg names the key-agreement algorithm the wallet should use with this
	// key. Wallets reject a JWK without it - OpenID4VP requires each key in
	// client_metadata.jwks to carry kty, crv, x, y and alg, and this key
	// previously carried every member except alg.
	if err := publicJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES()); err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}
