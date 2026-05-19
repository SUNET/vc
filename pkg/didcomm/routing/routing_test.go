package routing

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

func TestNewForward(t *testing.T) {
	mediatorDID := "did:example:mediator"
	nextDID := "did:example:recipient"
	wrappedMsg := []byte(`{"protected":"eyJ..."}`)

	forward := NewForward(mediatorDID, nextDID, wrappedMsg)

	if forward.Type != ForwardMessageType {
		t.Errorf("expected type %s, got %s", ForwardMessageType, forward.Type)
	}

	if forward.ID == "" {
		t.Error("expected non-empty ID")
	}

	if len(forward.To) != 1 || forward.To[0] != mediatorDID {
		t.Errorf("expected To=[%s], got %v", mediatorDID, forward.To)
	}

	if forward.Body.Next != nextDID {
		t.Errorf("expected Next=%s, got %s", nextDID, forward.Body.Next)
	}

	if len(forward.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(forward.Attachments))
	}

	if forward.Attachments[0].MediaType != "application/didcomm-encrypted+json" {
		t.Errorf("unexpected media type: %s", forward.Attachments[0].MediaType)
	}
}

func TestForwardGetWrappedMessage(t *testing.T) {
	wrappedMsg := []byte(`{"protected":"eyJ...","ciphertext":"abc"}`)
	forward := NewForward("did:example:mediator", "did:example:recipient", wrappedMsg)

	extracted, err := forward.GetWrappedMessage()
	if err != nil {
		t.Fatalf("failed to get wrapped message: %v", err)
	}

	if string(extracted) != string(wrappedMsg) {
		t.Errorf("wrapped message mismatch: got %s, want %s", extracted, wrappedMsg)
	}
}

func TestForwardToMessage(t *testing.T) {
	forward := NewForward("did:example:mediator", "did:example:recipient", []byte(`{}`))

	msg := forward.ToMessage()

	if msg.ID != forward.ID {
		t.Errorf("ID mismatch: got %s, want %s", msg.ID, forward.ID)
	}

	if msg.Type != ForwardMessageType {
		t.Errorf("type mismatch: got %s, want %s", msg.Type, ForwardMessageType)
	}

	body, ok := msg.Body.(map[string]any)
	if !ok {
		t.Fatal("body is not a map")
	}

	next, ok := body["next"].(string)
	if !ok || next != "did:example:recipient" {
		t.Errorf("next mismatch: got %v", body["next"])
	}
}

func TestParseForward(t *testing.T) {
	// Create a forward and convert to message, then parse back
	original := NewForward("did:example:mediator", "did:example:recipient", []byte(`{"test":"data"}`))
	msg := original.ToMessage()

	parsed, err := ParseForward(msg)
	if err != nil {
		t.Fatalf("failed to parse forward: %v", err)
	}

	if parsed.Body.Next != original.Body.Next {
		t.Errorf("next mismatch: got %s, want %s", parsed.Body.Next, original.Body.Next)
	}

	if len(parsed.Attachments) != len(original.Attachments) {
		t.Errorf("attachment count mismatch: got %d, want %d", len(parsed.Attachments), len(original.Attachments))
	}
}

func TestParseForwardFromJSON(t *testing.T) {
	forwardJSON := `{
		"id": "forward-1",
		"type": "https://didcomm.org/routing/2.0/forward",
		"to": ["did:example:mediator"],
		"body": {
			"next": "did:example:recipient"
		},
		"attachments": [{
			"id": "att-1",
			"media_type": "application/didcomm-encrypted+json",
			"data": {
				"json": {"protected": "eyJ...", "ciphertext": "abc"}
			}
		}]
	}`

	forward, err := ParseForwardFromJSON([]byte(forwardJSON))
	if err != nil {
		t.Fatalf("failed to parse forward from JSON: %v", err)
	}

	if forward.ID != "forward-1" {
		t.Errorf("ID mismatch: got %s", forward.ID)
	}

	if forward.Body.Next != "did:example:recipient" {
		t.Errorf("next mismatch: got %s", forward.Body.Next)
	}
}

func TestParseForwardInvalidType(t *testing.T) {
	msg := message.New(
		message.WithID("test-1"),
		message.WithType("https://example.org/wrong-type"),
	)

	_, err := ParseForward(msg)
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

func TestParseForwardMissingNext(t *testing.T) {
	msg := message.New(
		message.WithID("test-1"),
		message.WithType(ForwardMessageType),
		message.WithBody(map[string]any{}),
	)

	_, err := ParseForward(msg)
	if err != ErrMissingNext {
		t.Errorf("expected ErrMissingNext, got %v", err)
	}
}

// Mock implementations for testing

type mockEncrypter struct {
	encryptedMessages [][]byte
}

func (m *mockEncrypter) Encrypt(ctx context.Context, plaintext []byte, recipientDIDs []string) ([]byte, error) {
	// Just wrap in a simple JSON envelope for testing
	envelope := map[string]any{
		"encrypted_for": recipientDIDs,
		"ciphertext":    string(plaintext),
	}
	data, _ := json.Marshal(envelope)
	m.encryptedMessages = append(m.encryptedMessages, data)
	return data, nil
}

type mockDecrypter struct {
	decryptResult []byte
}

func (m *mockDecrypter) Decrypt(ctx context.Context, encrypted []byte) ([]byte, error) {
	if m.decryptResult != nil {
		return m.decryptResult, nil
	}
	// Parse the mock envelope
	var envelope map[string]any
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		return nil, err
	}
	ciphertext, ok := envelope["ciphertext"].(string)
	if !ok {
		return encrypted, nil
	}
	return []byte(ciphertext), nil
}

type mockServiceResolver struct {
	services map[string]*DIDCommService
}

func (m *mockServiceResolver) ResolveDIDCommService(ctx context.Context, did string) (*DIDCommService, error) {
	if s, ok := m.services[did]; ok {
		return s, nil
	}
	return nil, ErrNoRoute
}

func TestRouteBuilderDirectRoute(t *testing.T) {
	resolver := &mockServiceResolver{
		services: map[string]*DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: "https://recipient.example.com/didcomm",
				RoutingKeys:     nil, // No routing keys = direct delivery
			},
		},
	}

	builder := NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
	if err != nil {
		t.Fatalf("failed to build route: %v", err)
	}

	if !route.IsDirectRoute() {
		t.Error("expected direct route")
	}

	if route.MediatorCount() != 0 {
		t.Errorf("expected 0 mediators, got %d", route.MediatorCount())
	}

	if route.FinalRecipient != "did:example:recipient" {
		t.Errorf("final recipient mismatch: got %s", route.FinalRecipient)
	}
}

func TestRouteBuilderWithMediator(t *testing.T) {
	resolver := &mockServiceResolver{
		services: map[string]*DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: "https://mediator.example.com/didcomm",
				RoutingKeys:     []string{"did:example:mediator#key-1"},
			},
		},
	}

	builder := NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
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

	// First hop should be the mediator
	if route.Hops[0].RecipientDID != "did:example:mediator" {
		t.Errorf("first hop should be mediator, got %s", route.Hops[0].RecipientDID)
	}

	// Last hop should be the recipient
	if route.Hops[1].RecipientDID != "did:example:recipient" {
		t.Errorf("last hop should be recipient, got %s", route.Hops[1].RecipientDID)
	}
}

func TestRouteBuilderMultipleHops(t *testing.T) {
	resolver := &mockServiceResolver{
		services: map[string]*DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: "https://mediator1.example.com/didcomm",
				RoutingKeys: []string{
					"did:example:mediator1#key-1",
					"did:example:mediator2#key-2",
				},
			},
		},
	}

	builder := NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
	if err != nil {
		t.Fatalf("failed to build route: %v", err)
	}

	if route.MediatorCount() != 2 {
		t.Errorf("expected 2 mediators, got %d", route.MediatorCount())
	}

	if len(route.Hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(route.Hops))
	}
}

func TestWrapForRouteDirectDelivery(t *testing.T) {
	route := &Route{
		FinalRecipient: "did:example:recipient",
		Hops: []Hop{
			{RecipientDID: "did:example:recipient"},
		},
	}

	originalMsg := []byte(`{"original":"message"}`)
	encrypter := &mockEncrypter{}

	wrapped, err := WrapForRoute(context.Background(), originalMsg, route, encrypter)
	if err != nil {
		t.Fatalf("failed to wrap for route: %v", err)
	}

	// For direct routes, no wrapping should occur
	if string(wrapped) != string(originalMsg) {
		t.Errorf("direct route should not modify message")
	}

	if len(encrypter.encryptedMessages) != 0 {
		t.Error("direct route should not encrypt")
	}
}

func TestWrapForRouteSingleMediator(t *testing.T) {
	route := &Route{
		FinalRecipient: "did:example:recipient",
		Hops: []Hop{
			{RecipientDID: "did:example:mediator"},
			{RecipientDID: "did:example:recipient"},
		},
	}

	originalMsg := []byte(`{"encrypted":"for-recipient"}`)
	encrypter := &mockEncrypter{}

	wrapped, err := WrapForRoute(context.Background(), originalMsg, route, encrypter)
	if err != nil {
		t.Fatalf("failed to wrap for route: %v", err)
	}

	// Should have encrypted once (for the mediator)
	if len(encrypter.encryptedMessages) != 1 {
		t.Errorf("expected 1 encryption, got %d", len(encrypter.encryptedMessages))
	}

	// Wrapped message should be different from original
	if string(wrapped) == string(originalMsg) {
		t.Error("wrapped message should differ from original")
	}
}

func TestUnwrapForward(t *testing.T) {
	ctx := context.Background()

	// Create the inner encrypted message
	innerMsg := []byte(`{"protected":"inner","ciphertext":"data"}`)

	// Create a forward message
	forward := NewForward("did:example:mediator", "did:example:recipient", innerMsg)
	forwardJSON, _ := json.Marshal(forward.ToMessage())

	// Mock encrypter wraps the forward
	encrypter := &mockEncrypter{}
	encrypted, _ := encrypter.Encrypt(ctx, forwardJSON, []string{"did:example:mediator"})

	// Mock decrypter returns the forward JSON
	decrypter := &mockDecrypter{}

	// Unwrap
	inner, nextHop, err := UnwrapForward(ctx, encrypted, decrypter)
	if err != nil {
		t.Fatalf("failed to unwrap forward: %v", err)
	}

	if nextHop != "did:example:recipient" {
		t.Errorf("next hop mismatch: got %s", nextHop)
	}

	// Compare as JSON objects rather than raw bytes (key order may vary)
	var innerParsed, expectedParsed map[string]any
	if err := json.Unmarshal(inner, &innerParsed); err != nil {
		t.Fatalf("failed to parse inner message: %v", err)
	}
	if err := json.Unmarshal(innerMsg, &expectedParsed); err != nil {
		t.Fatalf("failed to parse expected message: %v", err)
	}

	if innerParsed["protected"] != expectedParsed["protected"] ||
		innerParsed["ciphertext"] != expectedParsed["ciphertext"] {
		t.Errorf("inner message mismatch: got %s", inner)
	}
}

func TestIsDIDKeyID(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"did:example:123#key-1", true},
		{"did:example:123", false},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false},
		{"did:key:z6Mk...#z6Mk...", true},
	}

	for _, tc := range tests {
		result := isDIDKeyID(tc.input)
		if result != tc.expected {
			t.Errorf("isDIDKeyID(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

func TestExtractDIDFromKeyID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"did:example:123#key-1", "did:example:123"},
		{"did:example:123", "did:example:123"},
		{"did:web:example.com#key-agreement-1", "did:web:example.com"},
	}

	for _, tc := range tests {
		result := extractDIDFromKeyID(tc.input)
		if result != tc.expected {
			t.Errorf("extractDIDFromKeyID(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestNewForwardWithID(t *testing.T) {
	forward := NewForwardWithID("custom-id", "did:example:mediator", "did:example:recipient", []byte(`{}`))

	if forward.ID != "custom-id" {
		t.Errorf("expected ID=custom-id, got %s", forward.ID)
	}
	if forward.Body.Next != "did:example:recipient" {
		t.Errorf("expected Next=did:example:recipient, got %s", forward.Body.Next)
	}
}

func TestWrapInForward(t *testing.T) {
	encrypted := []byte(`{"protected":"eyJ...","ciphertext":"abc"}`)
	forward := WrapInForward("did:example:mediator", "did:example:next", encrypted)

	if forward.Type != ForwardMessageType {
		t.Errorf("expected forward type, got %s", forward.Type)
	}

	wrapped, err := forward.GetWrappedMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var expected, actual any
	json.Unmarshal(encrypted, &expected)
	json.Unmarshal(wrapped, &actual)
	if expected == nil || actual == nil {
		t.Fatal("failed to parse JSON for comparison")
	}
}

func TestRoute_FirstHop(t *testing.T) {
	t.Run("empty route", func(t *testing.T) {
		route := &Route{}
		if route.FirstHop() != nil {
			t.Error("expected nil for empty route")
		}
	})

	t.Run("single hop", func(t *testing.T) {
		route := &Route{
			Hops: []Hop{{RecipientDID: "did:example:recipient", ServiceEndpoint: "https://example.com"}},
		}
		hop := route.FirstHop()
		if hop == nil {
			t.Fatal("expected non-nil hop")
		}
		if hop.RecipientDID != "did:example:recipient" {
			t.Errorf("expected did:example:recipient, got %s", hop.RecipientDID)
		}
	})
}

func TestRouteBuilder_WithMaxHops_ZeroMaxHops(t *testing.T) {
	resolver := &mockServiceResolver{
		services: map[string]*DIDCommService{
			"did:example:a": {
				ServiceEndpoint: "https://a.example.com",
				RoutingKeys:     []string{"did:example:b#key-1"},
			},
			"did:example:b": {
				ServiceEndpoint: "https://b.example.com",
			},
		},
	}

	// maxHops=0 should fail immediately since depth(0) >= maxHops(0)
	rb := NewRouteBuilder(resolver).WithMaxHops(0)

	_, err := rb.BuildRoute(context.Background(), "did:example:a")
	if err == nil {
		t.Error("expected error for zero max hops")
	}
}

func TestGetWrappedMessage_NoAttachments(t *testing.T) {
	forward := &Forward{
		Type: ForwardMessageType,
	}
	_, err := forward.GetWrappedMessage()
	if err == nil {
		t.Error("expected error for no attachments")
	}
}

func TestGetWrappedMessage_EmptyAttachment(t *testing.T) {
	forward := &Forward{
		Type:        ForwardMessageType,
		Attachments: []message.Attachment{{ID: "1"}},
	}
	_, err := forward.GetWrappedMessage()
	if err == nil {
		t.Error("expected error for empty attachment data")
	}
}
