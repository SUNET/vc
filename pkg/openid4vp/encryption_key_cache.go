package openid4vp

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
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
// GenerateAndStoreIfAbsent returns the public half of the key stored under
// kid, generating and storing a new pair only when there is none.
//
// Reuse matters because a request object can be produced more than once for
// the same session - GetOIDCRequestObject rebuilds and re-signs on every
// call. Generating afresh each time would overwrite the private key under
// an unchanged kid, so a wallet still holding an earlier request object
// would encrypt to a public key whose private half no longer exists, and
// the response would fail to decrypt with no obvious cause.
func (e *EphemeralEncryptionKeyCache) GenerateAndStoreIfAbsent(kid string) (jwk.Key, error) {
	if existing, found := e.Get(kid); found {
		publicKey, err := existing.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("deriving public key for kid %q: %w", kid, err)
		}
		// PublicKey copies the key material but not every parameter, so the
		// members a wallet requires are restored here rather than assumed.
		if err := decorateEncryptionKey(publicKey, kid); err != nil {
			return nil, err
		}
		return publicKey, nil
	}

	_, publicKey, err := e.GenerateAndStore(kid)
	return publicKey, err
}

// decorateEncryptionKey sets the parameters a wallet requires on a public
// encryption key: the key ID it is advertised under, its use, and the
// key-agreement algorithm to use with it.
func decorateEncryptionKey(key jwk.Key, kid string) error {
	if err := key.Set(jwk.KeyUsageKey, "enc"); err != nil {
		return err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ECDH_ES()); err != nil {
		return err
	}
	return key.Set(jwk.KeyIDKey, kid)
}

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

	// Sets use, alg and kid. alg in particular is required: OpenID4VP wants
	// each key in client_metadata.jwks to carry kty, crv, x, y and alg, and
	// this key previously carried every member except alg.
	if err := decorateEncryptionKey(publicJWK, kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}
