package didcomm_interop

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/SUNET/vc/pkg/didcomm/crypto"
	"github.com/SUNET/vc/pkg/didcomm/routing"
	"github.com/SUNET/vc/test/didcomm_interop/harness"
)

// TestRoutingForwardMessage tests forward message creation and parsing.
func TestRoutingForwardMessage(t *testing.T) {
	t.Run("create_and_parse", func(t *testing.T) {
		mediatorDID := "did:example:mediator"
		recipientDID := "did:example:recipient"
		innerMessage := []byte(`{"protected":"eyJ...","ciphertext":"abc123"}`)

		// Create forward
		forward := routing.NewForward(mediatorDID, recipientDID, innerMessage)

		if forward.Type != routing.ForwardMessageType {
			t.Errorf("expected type %s, got %s", routing.ForwardMessageType, forward.Type)
		}

		if forward.Body.Next != recipientDID {
			t.Errorf("expected next=%s, got %s", recipientDID, forward.Body.Next)
		}

		// Convert to JSON and back
		msg := forward.ToMessage()
		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		t.Logf("Forward message (%d bytes): %s", len(data), truncate(string(data), 100))

		// Parse back
		parsed, err := routing.ParseForwardFromJSON(data)
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if parsed.Body.Next != recipientDID {
			t.Errorf("parsed next mismatch: got %s", parsed.Body.Next)
		}

		// Extract wrapped message
		wrapped, err := parsed.GetWrappedMessage()
		if err != nil {
			t.Fatalf("failed to get wrapped message: %v", err)
		}

		// Compare as JSON (key order may vary)
		var original, extracted map[string]any
		json.Unmarshal(innerMessage, &original) // #nosec G104
		json.Unmarshal(wrapped, &extracted)     // #nosec G104

		if original["protected"] != extracted["protected"] {
			t.Errorf("wrapped message mismatch")
		}

		t.Log("✓ Forward message round-trip successful")
	})

	t.Run("with_attachment_id", func(t *testing.T) {
		forward := routing.NewForwardWithID(
			"forward-123",
			"did:example:mediator",
			"did:example:recipient",
			[]byte(`{"test":"data"}`),
		)

		if forward.ID != "forward-123" {
			t.Errorf("expected ID=forward-123, got %s", forward.ID)
		}

		if len(forward.Attachments) != 1 {
			t.Fatalf("expected 1 attachment, got %d", len(forward.Attachments))
		}

		if forward.Attachments[0].MediaType != "application/didcomm-encrypted+json" {
			t.Errorf("unexpected media type: %s", forward.Attachments[0].MediaType)
		}

		t.Log("✓ Forward with custom ID successful")
	})
}

// TestRoutingRouteBuilder tests route building from service endpoints.
func TestRoutingRouteBuilder(t *testing.T) {
	t.Run("direct_route", func(t *testing.T) {
		resolver := &mockServiceResolver{
			services: map[string]*routing.DIDCommService{
				"did:example:alice": {
					ServiceEndpoint: "https://alice.example.com/didcomm",
					RoutingKeys:     nil,
				},
			},
		}

		builder := routing.NewRouteBuilder(resolver)
		route, err := builder.BuildRoute(context.Background(), "did:example:alice")
		if err != nil {
			t.Fatalf("failed to build route: %v", err)
		}

		if !route.IsDirectRoute() {
			t.Error("expected direct route")
		}

		if route.MediatorCount() != 0 {
			t.Errorf("expected 0 mediators, got %d", route.MediatorCount())
		}

		t.Log("✓ Direct route build successful")
	})

	t.Run("single_mediator", func(t *testing.T) {
		resolver := &mockServiceResolver{
			services: map[string]*routing.DIDCommService{
				"did:example:bob": {
					ServiceEndpoint: "https://mediator.example.com/didcomm",
					RoutingKeys:     []string{"did:example:mediator#key-1"},
				},
			},
		}

		builder := routing.NewRouteBuilder(resolver)
		route, err := builder.BuildRoute(context.Background(), "did:example:bob")
		if err != nil {
			t.Fatalf("failed to build route: %v", err)
		}

		if route.IsDirectRoute() {
			t.Error("expected mediated route")
		}

		if route.MediatorCount() != 1 {
			t.Errorf("expected 1 mediator, got %d", route.MediatorCount())
		}

		if len(route.Hops) != 2 {
			t.Fatalf("expected 2 hops, got %d", len(route.Hops))
		}

		t.Log("✓ Single mediator route build successful")
	})

	t.Run("multi_hop", func(t *testing.T) {
		resolver := &mockServiceResolver{
			services: map[string]*routing.DIDCommService{
				"did:example:charlie": {
					ServiceEndpoint: "https://edge.example.com/didcomm",
					RoutingKeys: []string{
						"did:example:edge#key-1",
						"did:example:cloud#key-2",
					},
				},
			},
		}

		builder := routing.NewRouteBuilder(resolver)
		route, err := builder.BuildRoute(context.Background(), "did:example:charlie")
		if err != nil {
			t.Fatalf("failed to build route: %v", err)
		}

		if route.MediatorCount() != 2 {
			t.Errorf("expected 2 mediators, got %d", route.MediatorCount())
		}

		if len(route.Hops) != 3 {
			t.Fatalf("expected 3 hops, got %d", len(route.Hops))
		}

		t.Log("✓ Multi-hop route build successful")
	})
}

// TestRoutingWrapForRoute tests message wrapping for routes.
func TestRoutingWrapForRoute(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	t.Run("direct_no_wrapping", func(t *testing.T) {
		route := &routing.Route{
			FinalRecipient: "did:example:recipient",
			Hops: []routing.Hop{
				{RecipientDID: "did:example:recipient"},
			},
		}

		originalMsg := []byte(`{"original":"message"}`)

		// Direct routes should pass through unchanged
		wrapped, err := routing.WrapForRoute(ctx, originalMsg, route, &testEncrypter{testKeys})
		if err != nil {
			t.Fatalf("failed to wrap: %v", err)
		}

		if string(wrapped) != string(originalMsg) {
			t.Error("direct route should not modify message")
		}

		t.Log("✓ Direct route no wrapping successful")
	})

	t.Run("single_mediator_wrapping", func(t *testing.T) {
		route := &routing.Route{
			FinalRecipient: "did:example:bob",
			Hops: []routing.Hop{
				{RecipientDID: "did:example:mediator"},
				{RecipientDID: "did:example:bob"},
			},
		}

		// Simulate message already encrypted for final recipient
		innerMsg := []byte(`{"protected":"for-bob","ciphertext":"secret"}`)

		encrypter := &testEncrypter{testKeys}
		wrapped, err := routing.WrapForRoute(ctx, innerMsg, route, encrypter)
		if err != nil {
			t.Fatalf("failed to wrap: %v", err)
		}

		// Wrapped should be different (encrypted forward envelope)
		if string(wrapped) == string(innerMsg) {
			t.Error("wrapped message should differ from inner")
		}

		t.Logf("Wrapped message (%d bytes)", len(wrapped))
		t.Log("✓ Single mediator wrapping successful")
	})
}

// TestRoutingUnwrapForward tests unwrapping forward messages.
func TestRoutingUnwrapForward(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	t.Run("unwrap_at_mediator", func(t *testing.T) {
		// Create inner message (encrypted for final recipient)
		innerMsg := []byte(`{"protected":"for-bob","ciphertext":"secret-data"}`)

		// Create forward message
		forward := routing.NewForward("did:example:mediator", "did:example:bob", innerMsg)
		forwardJSON, _ := json.Marshal(forward.ToMessage())

		// Encrypt the forward for the mediator
		encrypted, err := crypto.Encrypt(ctx, forwardJSON, []jwk.Key{testKeys.BobX25519.PublicJWK}, crypto.DefaultEncryptionOptions())
		if err != nil {
			t.Fatalf("failed to encrypt forward: %v", err)
		}

		// Mediator decrypts and unwraps
		decrypter := &testDecrypter{testKeys, testKeys.BobX25519.PrivateJWK}
		inner, nextHop, err := routing.UnwrapForward(ctx, encrypted, decrypter)
		if err != nil {
			t.Fatalf("failed to unwrap: %v", err)
		}

		if nextHop != "did:example:bob" {
			t.Errorf("expected next hop=did:example:bob, got %s", nextHop)
		}

		// Verify inner message content
		var innerParsed map[string]any
		if err := json.Unmarshal(inner, &innerParsed); err != nil {
			t.Fatalf("failed to parse inner: %v", err)
		}

		if innerParsed["protected"] != "for-bob" {
			t.Errorf("inner message content mismatch")
		}

		t.Log("✓ Forward unwrap at mediator successful")
	})
}

// Helper types for testing

type mockServiceResolver struct {
	services map[string]*routing.DIDCommService
}

func (m *mockServiceResolver) ResolveDIDCommService(ctx context.Context, did string) (*routing.DIDCommService, error) {
	if s, ok := m.services[did]; ok {
		return s, nil
	}
	return nil, routing.ErrNoRoute
}

type testEncrypter struct {
	keys *harness.TestKeys
}

func (e *testEncrypter) Encrypt(ctx context.Context, plaintext []byte, recipientDIDs []string) ([]byte, error) {
	// Use the first recipient's X25519 key for testing
	return crypto.Encrypt(ctx, plaintext, []jwk.Key{e.keys.BobX25519.PublicJWK}, crypto.DefaultEncryptionOptions())
}

type testDecrypter struct {
	keys       *harness.TestKeys
	privateKey jwk.Key
}

func (d *testDecrypter) Decrypt(ctx context.Context, encrypted []byte) ([]byte, error) {
	return crypto.Decrypt(ctx, encrypted, d.privateKey)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
