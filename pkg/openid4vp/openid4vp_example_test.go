package openid4vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ExampleNew demonstrates creating an OpenID4VP client with default settings
func ExampleNew() {
	ctx := t.Context()

	// Create a client with default TTL settings (10 minutes for both caches)
	client, err := openid4vp.New(ctx, nil)
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("Client created with default settings")
	fmt.Printf("Ephemeral key cache initialized: %t\n", client.EphemeralKeyCache != nil)
	fmt.Printf("Request object cache initialized: %t\n", client.RequestObjectCache != nil)

	// Output:
	// Client created with default settings
	// Ephemeral key cache initialized: true
	// Request object cache initialized: true
}

// ExampleNew_withCustomConfig demonstrates creating a client with custom TTL settings
func ExampleNew_withCustomConfig() {
	ctx := t.Context()

	// Create a client with custom TTL values
	config := &openid4vp.Config{
		EphemeralKeyTTL:  5 * time.Minute, // Ephemeral keys expire after 5 minutes
		RequestObjectTTL: 3 * time.Minute, // Request objects expire after 3 minutes
	}

	client, err := openid4vp.New(ctx, config)
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("Client created with custom TTL settings")
	fmt.Printf("Ephemeral key cache TTL: 5 minutes\n")
	fmt.Printf("Request object cache TTL: 3 minutes\n")

	// Output:
	// Client created with custom TTL settings
	// Ephemeral key cache TTL: 5 minutes
	// Request object cache TTL: 3 minutes
}

// ExampleNew_usage demonstrates using both caches in the client
func ExampleNew_usage() {
	ctx := t.Context()

	// Create client
	client, err := openid4vp.New(ctx, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer client.Close()

	// 1. Store a request object in the request object cache
	requestObject := &openid4vp.RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
		Nonce:        "n-0S6_WzA2Mj",
		State:        "af0ifjsldkj",
	}
	requestURI := "urn:ietf:params:oauth:request_uri:6eSG8FrjKQb1Qiwj"
	client.RequestObjectCache.Set(requestURI, requestObject)

	// Retrieve the request object
	retrieved, found := client.RequestObjectCache.Get(requestURI)
	if found {
		fmt.Printf("Request object - Client: %s\n", retrieved.ClientID)
		fmt.Printf("Request object - State: %s\n", retrieved.State)
	}

	// 2. Store an ephemeral encryption key in the ephemeral key cache
	// Generate a test key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := jwk.Import(privateKey)
	_ = key.Set(jwk.KeyIDKey, "ephemeral-key-123")

	client.EphemeralKeyCache.Set("ephemeral-key-123", key)

	// Retrieve the ephemeral key
	retrievedKey, found := client.EphemeralKeyCache.Get("ephemeral-key-123")
	if found {
		kid, _ := retrievedKey.KeyID()
		fmt.Printf("Ephemeral key - KID: %s\n", kid)
	}

	// Check both cache sizes
	fmt.Printf("Request objects in cache: %d\n", client.RequestObjectCache.Len())
	fmt.Printf("Ephemeral keys in cache: %d\n", client.EphemeralKeyCache.Len())

	// Output:
	// Request object - Client: https://verifier.example.com
	// Request object - State: af0ifjsldkj
	// Ephemeral key - KID: ephemeral-key-123
	// Request objects in cache: 1
	// Ephemeral keys in cache: 1
}
