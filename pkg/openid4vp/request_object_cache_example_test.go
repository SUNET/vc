package openid4vp_test

import (
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// ExampleNewRequestObjectCache demonstrates creating a request object cache
func ExampleNewRequestObjectCache() {
	// Create a cache with 10-minute TTL
	cache := openid4vp.NewRequestObjectCache(10 * time.Minute)
	defer cache.Stop()

	// Store a request object
	requestURI := "urn:ietf:params:oauth:request_uri:6eSG8FrjKQb1Qiwj"
	requestObject := &openid4vp.RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
		Nonce:        "n-0S6_WzA2Mj",
	}
	cache.Set(requestURI, requestObject)

	// Retrieve the request object
	retrieved, found := cache.Get(requestURI)
	if found {
		fmt.Printf("Found request object for client: %s\n", retrieved.ClientID)
	}

	// Output:
	// Found request object for client: https://verifier.example.com
}

// ExampleRequestObjectCache_SetWithTTL demonstrates setting a request object with custom TTL
func ExampleRequestObjectCache_SetWithTTL() {
	cache := openid4vp.NewRequestObjectCache(openid4vp.DefaultRequestObjectTTL)
	defer cache.Stop()

	// Store a request object with a custom short TTL (e.g., for one-time use)
	requestURI := "urn:ietf:params:oauth:request_uri:short-lived"
	requestObject := &openid4vp.RequestObject{
		ResponseType: "vp_token",
		ClientID:     "https://verifier.example.com",
		Nonce:        "n-abc123",
	}

	// Set with 5-minute TTL instead of default 10 minutes
	cache.SetWithTTL(requestURI, requestObject, 5*time.Minute)

	fmt.Printf("Stored request object with 5-minute TTL\n")

	// Output:
	// Stored request object with 5-minute TTL
}
