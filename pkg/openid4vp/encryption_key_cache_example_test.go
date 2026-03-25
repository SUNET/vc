package openid4vp_test

import (
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// ExampleNewEphemeralEncryptionKeyCache demonstrates creating an ephemeral encryption key cache
func ExampleNewEphemeralEncryptionKeyCache() {
	// Create a cache with 10-minute TTL
	cache := openid4vp.NewEphemeralEncryptionKeyCache(10 * time.Minute)
	defer cache.Stop()

	fmt.Println("Ephemeral encryption key cache created")
	fmt.Printf("Initial cache size: %d\n", cache.Len())

	// Output:
	// Ephemeral encryption key cache created
	// Initial cache size: 0
}

// ExampleEphemeralEncryptionKeyCache_GenerateAndStore demonstrates generating and storing a key pair
func ExampleEphemeralEncryptionKeyCache_GenerateAndStore() {
	cache := openid4vp.NewEphemeralEncryptionKeyCache(openid4vp.DefaultEphemeralKeyTTL)
	defer cache.Stop()

	// Generate ECDH P-256 key pair and store private key in cache
	kid := "ephemeral-key-abc123"
	privateKey, publicKey, err := cache.GenerateAndStore(kid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Private key is automatically stored in cache
	retrievedPrivate, found := cache.Get(kid)
	if found {
		fmt.Printf("Private key stored in cache: %t\n", retrievedPrivate != nil)
	}

	// Get key IDs
	privateKid, _ := privateKey.KeyID()
	publicKid, _ := publicKey.KeyID()
	fmt.Printf("Private key KID: %s\n", privateKid)
	fmt.Printf("Public key KID: %s\n", publicKid)

	// Public key has "use" set to "enc"
	use, _ := publicKey.KeyUsage()
	fmt.Printf("Public key usage: %s\n", use)

	// Output:
	// Private key stored in cache: true
	// Private key KID: ephemeral-key-abc123
	// Public key KID: ephemeral-key-abc123
	// Public key usage: enc
}
