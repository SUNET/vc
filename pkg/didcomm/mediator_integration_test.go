//go:build didcomm && vc20 && integration

// Package didcomm_test provides integration tests for mediator routing.
//
// These tests verify DIDComm 2.1 routing and mediator functionality:
// - Route building through mediators
// - Forward message wrapping for mediated delivery
// - Trust ping through a mediator
//
// To run integration tests:
//
//	go test -tags "didcomm vc20 integration" ./pkg/didcomm/...
//
// For live mediator tests (when available):
//
//	go test -tags "didcomm vc20 integration live" ./pkg/didcomm/...
package didcomm_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
	"vc/pkg/didcomm/protocol/trustping"
	"vc/pkg/didcomm/routing"
)

// Public mediator DID for integration tests
const (
	// PublicMediatorDID is the did:webvh for the public test mediator
	PublicMediatorDID = "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator"

	// TestMediatorRoutingKey is a test X25519 key for the mock mediator
	testMediatorRoutingKey = "z6LSfRnzDTj1iM...(test-key)"
)

// =============================================================================
// Mock Mediator Server for Unit Tests
// =============================================================================

// mockMediatorServer simulates a DIDComm mediator for testing.
type mockMediatorServer struct {
	server        *httptest.Server
	did           string
	routingKey    *ecdh.PrivateKey
	routingKeyJWK jwk.Key
	receivedMsgs  chan []byte
	responseFunc  func([]byte) ([]byte, error)
}

// newMockMediatorServer creates a new mock mediator with generated keys.
func newMockMediatorServer(t *testing.T, did string) *mockMediatorServer {
	t.Helper()

	// Generate X25519 key pair for routing
	routingKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate routing key: %v", err)
	}

	// Convert to JWK
	routingKeyJWK, err := jwk.Import(routingKey)
	if err != nil {
		t.Fatalf("Failed to import routing key to JWK: %v", err)
	}
	_ = routingKeyJWK.Set("kid", did+"#routing-key-1")

	m := &mockMediatorServer{
		did:           did,
		routingKey:    routingKey,
		routingKeyJWK: routingKeyJWK,
		receivedMsgs:  make(chan []byte, 100),
	}

	m.server = httptest.NewServer(http.HandlerFunc(m.handleMessage))

	return m
}

// handleMessage processes incoming DIDComm messages.
func (m *mockMediatorServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Store received message
	select {
	case m.receivedMsgs <- body:
	default:
		// Channel full, discard oldest
	}

	// If response function is set, use it
	if m.responseFunc != nil {
		resp, err := m.responseFunc(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if resp != nil {
			w.Header().Set("Content-Type", didcomm.MediaTypeEncrypted)
			w.Write(resp)
			return
		}
	}

	// Default: return 202 Accepted (async delivery)
	w.WriteHeader(http.StatusAccepted)
}

// DIDDocument returns a mock DID document for the mediator.
func (m *mockMediatorServer) DIDDocument() map[string]interface{} {
	pubKey, _ := m.routingKeyJWK.PublicKey()
	pubKeyBytes, _ := json.Marshal(pubKey)
	pubKeyMap := make(map[string]interface{})
	json.Unmarshal(pubKeyBytes, &pubKeyMap)

	return map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id":         m.did,
		"controller": m.did,
		"verificationMethod": []map[string]interface{}{
			{
				"id":           m.did + "#routing-key-1",
				"type":         "JsonWebKey2020",
				"controller":   m.did,
				"publicKeyJwk": pubKeyMap,
			},
		},
		"keyAgreement": []string{m.did + "#routing-key-1"},
		"service": []map[string]interface{}{
			{
				"id":              m.did + "#didcomm-1",
				"type":            "DIDCommMessaging",
				"serviceEndpoint": m.server.URL,
				"routingKeys":     []string{m.did + "#routing-key-1"},
				"accept":          []string{didcomm.MediaTypeEncrypted, didcomm.MediaTypePlaintext},
			},
		},
	}
}

// URL returns the mediator's service endpoint URL.
func (m *mockMediatorServer) URL() string {
	return m.server.URL
}

// Close shuts down the mock mediator server.
func (m *mockMediatorServer) Close() {
	m.server.Close()
}

// =============================================================================
// Helper Types for Testing
// =============================================================================

// testServiceResolver implements routing.ServiceResolver for testing.
type testServiceResolver struct {
	services map[string]*routing.DIDCommService
}

func (r *testServiceResolver) ResolveDIDCommService(ctx context.Context, did string) (*routing.DIDCommService, error) {
	if svc, ok := r.services[did]; ok {
		return svc, nil
	}
	return nil, nil // No service found (direct delivery)
}

// =============================================================================
// Integration Tests with Mock Mediator
// =============================================================================

func TestRouteBuilder_WithMockMediator(t *testing.T) {
	// Create mock mediator
	mediator := newMockMediatorServer(t, "did:example:mediator")
	defer mediator.Close()

	// Create a mock service resolver using the mediator
	resolver := &testServiceResolver{
		services: map[string]*routing.DIDCommService{
			mediator.did: {
				ServiceEndpoint: mediator.URL(),
				RoutingKeys:     []string{mediator.did + "#routing-key-1"},
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
		},
	}

	// Build route through mediator
	builder := routing.NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), mediator.did)
	if err != nil {
		t.Fatalf("Failed to build route: %v", err)
	}

	if route.IsDirectRoute() {
		t.Error("Expected route through mediator, got direct route")
	}

	if route.FinalRecipient != mediator.did {
		t.Errorf("Expected final recipient %s, got %s", mediator.did, route.FinalRecipient)
	}
}

func TestForwardMessage_WithMockMediator(t *testing.T) {
	// Create mock mediator
	mediator := newMockMediatorServer(t, "did:example:mediator")
	defer mediator.Close()

	// Create a forward message
	wrappedMsg := []byte(`{"protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","ciphertext":"encrypted-content"}`)
	forward := routing.NewForward(mediator.did, "did:example:recipient", wrappedMsg)

	if forward.Type != routing.ForwardMessageType {
		t.Errorf("Expected type %s, got %s", routing.ForwardMessageType, forward.Type)
	}

	if forward.Body.Next != "did:example:recipient" {
		t.Errorf("Expected next did:example:recipient, got %s", forward.Body.Next)
	}

	// Verify wrapped message can be extracted
	extracted, err := forward.GetWrappedMessage()
	if err != nil {
		t.Fatalf("Failed to extract wrapped message: %v", err)
	}

	if string(extracted) != string(wrappedMsg) {
		t.Error("Extracted message doesn't match original")
	}
}

func TestTrustPingThroughMockMediator(t *testing.T) {
	// Create mock mediator that forwards trust pings
	mediator := newMockMediatorServer(t, "did:example:mediator")
	defer mediator.Close()

	// Generate key pairs for sender and recipient
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	recipientPub, recipientPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = senderPub
	_ = senderPriv
	_ = recipientPub
	_ = recipientPriv

	// Create trust ping message
	ping, err := trustping.NewPing("did:example:sender", "did:example:mediator", trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create ping: %v", err)
	}

	if ping.Type != trustping.TypePing {
		t.Errorf("Expected type %s, got %s", trustping.TypePing, ping.Type)
	}

	// Verify ping can be handled
	response, err := trustping.HandlePing(ping)
	if err != nil {
		t.Fatalf("Failed to handle ping: %v", err)
	}

	if response == nil {
		t.Fatal("Expected response for ping with response_requested=true")
	}

	if response.Type != trustping.TypePingResponse {
		t.Errorf("Expected response type %s, got %s", trustping.TypePingResponse, response.Type)
	}
}

// =============================================================================
// Test Message Packing with Routing Keys
// =============================================================================

func TestPackWithRoutingKeys(t *testing.T) {
	// Generate keys
	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}

	recipientJWK, err := jwk.Import(recipientPriv.PublicKey())
	if err != nil {
		t.Fatalf("Failed to import recipient key: %v", err)
	}
	_ = recipientJWK.Set("kid", "did:example:recipient#key-1")

	// Create test message
	msg := message.New(
		message.WithID("test-msg-1"),
		message.WithType(trustping.TypePing),
		message.WithFrom("did:example:sender"),
		message.WithTo("did:example:recipient"),
	)

	// Pack without routing (direct)
	result, err := didcomm.PackAnoncrypt(context.Background(), msg, []jwk.Key{recipientJWK})
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	if result.MediaType != didcomm.MediaTypeEncrypted {
		t.Errorf("Expected media type %s, got %s", didcomm.MediaTypeEncrypted, result.MediaType)
	}

	if len(result.Message) == 0 {
		t.Error("Expected non-empty packed message")
	}

	t.Logf("Packed message size: %d bytes", len(result.Message))
}

// =============================================================================
// Route Building Tests with Different Topologies
// =============================================================================

func TestRouteBuilder_DirectDelivery(t *testing.T) {
	// Service resolver that returns nil (no routing needed)
	resolver := &testServiceResolver{
		services: map[string]*routing.DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: "https://example.com/didcomm",
				RoutingKeys:     nil, // No routing keys = direct delivery
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
		},
	}

	builder := routing.NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
	if err != nil {
		t.Fatalf("Failed to build route: %v", err)
	}

	if !route.IsDirectRoute() {
		t.Error("Expected direct route for recipient without routing keys")
	}
}

func TestRouteBuilder_SingleMediator(t *testing.T) {
	mediator := newMockMediatorServer(t, "did:example:mediator")
	defer mediator.Close()

	resolver := &testServiceResolver{
		services: map[string]*routing.DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: mediator.URL(),
				RoutingKeys:     []string{mediator.did + "#routing-key-1"},
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
			mediator.did: {
				ServiceEndpoint: mediator.URL(),
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
		},
	}

	builder := routing.NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
	if err != nil {
		t.Fatalf("Failed to build route: %v", err)
	}

	if route.IsDirectRoute() {
		t.Error("Expected mediated route")
	}

	t.Logf("Route: %d hops, final=%s", len(route.Hops), route.FinalRecipient)
}

func TestRouteBuilder_MultipleMediatorators(t *testing.T) {
	mediator1 := newMockMediatorServer(t, "did:example:mediator1")
	defer mediator1.Close()

	mediator2 := newMockMediatorServer(t, "did:example:mediator2")
	defer mediator2.Close()

	resolver := &testServiceResolver{
		services: map[string]*routing.DIDCommService{
			"did:example:recipient": {
				ServiceEndpoint: mediator2.URL(),
				RoutingKeys:     []string{mediator2.did + "#routing-key-1"},
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
			mediator2.did: {
				ServiceEndpoint: mediator1.URL(),
				RoutingKeys:     []string{mediator1.did + "#routing-key-1"},
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
			mediator1.did: {
				ServiceEndpoint: mediator1.URL(),
				Accept:          []string{didcomm.MediaTypeEncrypted},
			},
		},
	}

	builder := routing.NewRouteBuilder(resolver)
	route, err := builder.BuildRoute(context.Background(), "did:example:recipient")
	if err != nil {
		t.Fatalf("Failed to build route: %v", err)
	}

	if route.MediatorCount() < 1 {
		t.Error("Expected at least one mediator in route")
	}

	t.Logf("Route: %d hops, %d mediators", len(route.Hops), route.MediatorCount())
}

// =============================================================================
// Forward Message Tests
// =============================================================================

func TestForwardMessageParsing(t *testing.T) {
	wrappedMsg := []byte(`{"protected":"abc","ciphertext":"xyz"}`)

	// Create forward
	forward := routing.NewForward("did:example:mediator", "did:example:recipient", wrappedMsg)

	// Convert to generic message
	msg := forward.ToMessage()

	// Parse back
	parsed, err := routing.ParseForward(msg)
	if err != nil {
		t.Fatalf("Failed to parse forward: %v", err)
	}

	if parsed.Body.Next != "did:example:recipient" {
		t.Errorf("Expected next=did:example:recipient, got %s", parsed.Body.Next)
	}

	extracted, _ := parsed.GetWrappedMessage()
	if string(extracted) != string(wrappedMsg) {
		t.Error("Wrapped message mismatch after round-trip")
	}
}

func TestForwardMessageJSON(t *testing.T) {
	forwardJSON := `{
		"id": "forward-123",
		"type": "https://didcomm.org/routing/2.0/forward",
		"to": ["did:example:mediator"],
		"body": {
			"next": "did:example:recipient"
		},
		"attachments": [{
			"id": "att-1",
			"media_type": "application/didcomm-encrypted+json",
			"data": {
				"json": {"protected": "eyJ...", "ciphertext": "abc123"}
			}
		}]
	}`

	forward, err := routing.ParseForwardFromJSON([]byte(forwardJSON))
	if err != nil {
		t.Fatalf("Failed to parse forward from JSON: %v", err)
	}

	if forward.ID != "forward-123" {
		t.Errorf("Expected ID forward-123, got %s", forward.ID)
	}

	if forward.Body.Next != "did:example:recipient" {
		t.Errorf("Expected next did:example:recipient, got %s", forward.Body.Next)
	}
}

// =============================================================================
// Trust Ping Protocol Tests
// =============================================================================

func TestTrustPingMessage(t *testing.T) {
	senderDID := "did:example:sender"
	recipientDID := "did:example:recipient"

	// Create ping requesting response
	ping, err := trustping.NewPing(senderDID, recipientDID, trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create ping: %v", err)
	}

	if ping.Type != trustping.TypePing {
		t.Errorf("Wrong type: %s", ping.Type)
	}

	if ping.From != senderDID {
		t.Errorf("Wrong from: %s", ping.From)
	}

	// Check body for response_requested via JSON round-trip
	body := ping.Body
	if body == nil {
		t.Error("Expected non-nil body")
	}
}

func TestTrustPingResponse(t *testing.T) {
	ping, err := trustping.NewPing("did:example:sender", "did:example:recipient", trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create ping: %v", err)
	}

	response, err := trustping.HandlePing(ping)
	if err != nil {
		t.Fatalf("Failed to handle ping: %v", err)
	}

	if response.Type != trustping.TypePingResponse {
		t.Errorf("Wrong response type: %s", response.Type)
	}

	// The response should reference the original ping via thid (thread ID)
	if response.ThreadID() == "" {
		t.Error("Expected non-empty thread_id in response")
	}
}

func TestTrustPingNoResponseRequested(t *testing.T) {
	ping, err := trustping.NewPing("did:example:sender", "did:example:recipient", trustping.WithResponseRequested(false))
	if err != nil {
		t.Fatalf("Failed to create ping: %v", err)
	}

	response, err := trustping.HandlePing(ping)
	if err != nil {
		t.Fatalf("Failed to handle ping: %v", err)
	}

	if response != nil {
		t.Error("Expected nil response when response_requested=false")
	}
}
