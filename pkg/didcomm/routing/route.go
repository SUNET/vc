package routing

import (
	"context"
	"fmt"
)

// DefaultMaxHops is the default maximum number of routing hops allowed.
const DefaultMaxHops = 10

// Hop represents a single hop in a routing path.
type Hop struct {
	// RecipientDID is the DID that should receive the message at this hop.
	// This is used for encryption (Encrypter interface requires DIDs).
	RecipientDID string

	// RoutingKey is the original key ID from the service endpoint.
	// May be a DID URL (e.g., did:example:mediator#key-1) or a DID.
	// The Encrypter uses RecipientDID (extracted from RoutingKey if needed)
	// since the encryption interface operates on DIDs, not key IDs.
	RoutingKey string

	// ServiceEndpoint is the endpoint URL for this hop (if known).
	ServiceEndpoint string
}

// Route represents a complete routing path from sender to final recipient.
type Route struct {
	// Hops is the sequence of hops from first mediator to final recipient.
	// The last hop is always the final recipient.
	Hops []Hop

	// FinalRecipient is the DID of the ultimate message recipient.
	FinalRecipient string
}

// IsDirectRoute returns true if no mediators are involved.
func (r *Route) IsDirectRoute() bool {
	return len(r.Hops) <= 1
}

// MediatorCount returns the number of mediators in the route.
func (r *Route) MediatorCount() int {
	if len(r.Hops) <= 1 {
		return 0
	}
	return len(r.Hops) - 1
}

// FirstHop returns the first hop (first mediator or direct recipient).
func (r *Route) FirstHop() *Hop {
	if len(r.Hops) == 0 {
		return nil
	}
	return &r.Hops[0]
}

// ServiceResolver resolves DIDComm service endpoints from DIDs.
type ServiceResolver interface {
	// ResolveDIDCommService resolves DIDComm service endpoint information.
	ResolveDIDCommService(ctx context.Context, did string) (*DIDCommService, error)
}

// DIDCommService represents a DIDCommMessaging service endpoint.
type DIDCommService struct {
	// ServiceEndpoint is the URI for the service.
	ServiceEndpoint string

	// RoutingKeys are the keys to use for routing to this endpoint.
	// May be empty for direct delivery.
	RoutingKeys []string

	// Accept lists accepted message content types.
	Accept []string
}

// RouteBuilder constructs routes to recipients.
type RouteBuilder struct {
	resolver ServiceResolver
	maxHops  int
}

// NewRouteBuilder creates a new route builder with the given resolver.
func NewRouteBuilder(resolver ServiceResolver) *RouteBuilder {
	return &RouteBuilder{
		resolver: resolver,
		maxHops:  DefaultMaxHops,
	}
}

// WithMaxHops sets the maximum number of hops allowed.
func (rb *RouteBuilder) WithMaxHops(max int) *RouteBuilder {
	rb.maxHops = max
	return rb
}

// BuildRoute constructs a route to the given recipient.
// It resolves the recipient's DIDComm service and any routing keys.
func (rb *RouteBuilder) BuildRoute(ctx context.Context, recipientDID string) (*Route, error) {
	return rb.buildRouteRecursive(ctx, recipientDID, 0)
}

func (rb *RouteBuilder) buildRouteRecursive(ctx context.Context, did string, depth int) (*Route, error) {
	if depth >= rb.maxHops {
		return nil, ErrMaxHopsExceeded
	}

	// Resolve the DID's service endpoint
	service, err := rb.resolver.ResolveDIDCommService(ctx, did)
	if err != nil {
		// Fallback to direct delivery when service resolution fails.
		// This allows sending to DIDs that don't publish DIDComm services,
		// treating them as direct recipients. Callers should handle this
		// by attempting direct delivery or reporting the missing endpoint.
		return &Route{
			FinalRecipient: did,
			Hops: []Hop{
				{RecipientDID: did},
			},
		}, nil
	}

	// If no routing keys, this is a direct endpoint
	if len(service.RoutingKeys) == 0 {
		return &Route{
			FinalRecipient: did,
			Hops: []Hop{
				{
					RecipientDID:    did,
					ServiceEndpoint: service.ServiceEndpoint,
				},
			},
		}, nil
	}

	// Build route through routing keys (mediators)
	var hops []Hop

	// Add mediator hops for each routing key
	for i, routingKey := range service.RoutingKeys {
		// The routing key might be a DID or a key ID
		mediatorDID := routingKey
		if isDIDKeyID(routingKey) {
			// Extract DID from key ID (e.g., "did:example:mediator#key-1" -> "did:example:mediator")
			mediatorDID = extractDIDFromKeyID(routingKey)
		}

		hop := Hop{
			RecipientDID: mediatorDID,
			RoutingKey:   routingKey,
		}

		// First routing key's endpoint is the service endpoint
		if i == 0 {
			hop.ServiceEndpoint = service.ServiceEndpoint
		}

		hops = append(hops, hop)
	}

	// Add final recipient as the last hop
	hops = append(hops, Hop{
		RecipientDID: did,
	})

	return &Route{
		FinalRecipient: did,
		Hops:           hops,
	}, nil
}

// WrapForRoute wraps a message with forward envelopes for the given route.
// The message should already be encrypted for the final recipient.
// This function adds forward wrappers for each mediator hop.
func WrapForRoute(ctx context.Context, encryptedForRecipient []byte, route *Route, encrypter Encrypter) ([]byte, error) {
	if route.IsDirectRoute() {
		// No wrapping needed for direct routes
		return encryptedForRecipient, nil
	}

	// Start with the innermost message (encrypted for final recipient)
	currentMessage := encryptedForRecipient

	// Work backwards through the hops (excluding the final recipient)
	// to wrap in forward envelopes
	for i := len(route.Hops) - 2; i >= 0; i-- {
		mediatorHop := route.Hops[i]
		nextHop := route.Hops[i+1]

		// Create forward message pointing to the next hop
		forward := NewForward(mediatorHop.RecipientDID, nextHop.RecipientDID, currentMessage)

		// Serialize the forward message
		forwardJSON, err := forward.ToMessage().MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize forward message: %w", err)
		}

		// Encrypt the forward for this mediator
		encrypted, err := encrypter.Encrypt(ctx, forwardJSON, []string{mediatorHop.RecipientDID})
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt for mediator %s: %w", mediatorHop.RecipientDID, err)
		}

		currentMessage = encrypted
	}

	return currentMessage, nil
}

// Helper functions

func isDIDKeyID(s string) bool {
	// Key IDs contain '#'
	for _, c := range s {
		if c == '#' {
			return true
		}
	}
	return false
}

func extractDIDFromKeyID(keyID string) string {
	for i, c := range keyID {
		if c == '#' {
			return keyID[:i]
		}
	}
	return keyID
}
