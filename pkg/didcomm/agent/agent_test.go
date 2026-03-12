package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
	"vc/pkg/didcomm/protocol/discoverfeatures"
	"vc/pkg/didcomm/protocol/trustping"
)

// mockKeyStore implements KeyStore for testing.
type mockKeyStore struct {
	keys    map[string]jwk.Key
	keyList []string
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{keys: make(map[string]jwk.Key)}
}

func (ks *mockKeyStore) GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error) {
	if key, ok := ks.keys[kid]; ok {
		return key, nil
	}
	return nil, ErrNoPrivateKey
}

func (ks *mockKeyStore) ListKeyIDs(ctx context.Context) ([]string, error) {
	return ks.keyList, nil
}

func (ks *mockKeyStore) AddKey(kid string, key jwk.Key) {
	ks.keys[kid] = key
	ks.keyList = append(ks.keyList, kid)
}

// mockKeyResolver implements KeyResolver for testing.
type mockKeyResolver struct {
	agreementKeys    map[string][]jwk.Key
	verificationKeys map[string][]jwk.Key
}

func newMockKeyResolver() *mockKeyResolver {
	return &mockKeyResolver{
		agreementKeys:    make(map[string][]jwk.Key),
		verificationKeys: make(map[string][]jwk.Key),
	}
}

func (r *mockKeyResolver) ResolveKeyAgreement(ctx context.Context, did string) ([]jwk.Key, error) {
	if keys, ok := r.agreementKeys[did]; ok {
		return keys, nil
	}
	return nil, nil
}

func (r *mockKeyResolver) ResolveVerification(ctx context.Context, did string) ([]jwk.Key, error) {
	if keys, ok := r.verificationKeys[did]; ok {
		return keys, nil
	}
	return nil, nil
}

// mockEndpointResolver implements EndpointResolver for testing.
type mockEndpointResolver struct {
	endpoints map[string]string
}

func newMockEndpointResolver() *mockEndpointResolver {
	return &mockEndpointResolver{endpoints: make(map[string]string)}
}

func (r *mockEndpointResolver) ResolveEndpoint(ctx context.Context, did string) (string, error) {
	if endpoint, ok := r.endpoints[did]; ok {
		return endpoint, nil
	}
	return "", ErrNoEndpoint
}

// generateX25519KeyPair generates a new X25519 key pair as JWK.
func generateX25519KeyPair(t *testing.T, kid string) (jwk.Key, jwk.Key) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	privateJWK, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("Failed to import private key: %v", err)
	}
	_ = privateJWK.Set("kid", kid)

	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	_ = publicJWK.Set("kid", kid)

	return privateJWK, publicJWK
}

func TestNew(t *testing.T) {
	agent, err := New(
		WithDID("did:example:alice"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if agent.DID() != "did:example:alice" {
		t.Errorf("DID() = %v, want did:example:alice", agent.DID())
	}
}

func TestAgent_RegisterHandler(t *testing.T) {
	agent, _ := New()

	handler := func(ctx context.Context, msg *message.Message) (*message.Message, error) {
		return nil, nil
	}

	agent.RegisterHandler("https://example.com/test", handler)

	// Verify handler is registered
	agent.handlersMu.RLock()
	_, exists := agent.handlers["https://example.com/test"]
	agent.handlersMu.RUnlock()

	if !exists {
		t.Error("handler not registered")
	}
}

func TestAgent_ProcessMessage_TrustPing(t *testing.T) {
	agent, _ := New(WithDID("did:example:bob"))

	// Create a ping message
	ping, _ := trustping.NewPing("did:example:alice", "did:example:bob")
	pingBytes, _ := ping.MarshalJSON()

	// Process
	responseBytes, mediaType, err := agent.ProcessMessage(context.Background(), pingBytes, "application/didcomm-plain+json")
	if err != nil {
		t.Fatalf("ProcessMessage() error = %v", err)
	}

	if responseBytes == nil {
		t.Error("expected response for ping")
	}

	if mediaType == "" {
		t.Error("expected media type")
	}

	// Parse response
	response, err := message.Parse(responseBytes)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Type != trustping.TypePingResponse {
		t.Errorf("response type = %v, want %v", response.Type, trustping.TypePingResponse)
	}
}

func TestAgent_ProcessMessage_NoHandler(t *testing.T) {
	agent, _ := New()

	// Create an unknown message type
	msg := message.New(message.WithType("https://example.com/unknown"))
	msgBytes, _ := msg.MarshalJSON()

	_, _, err := agent.ProcessMessage(context.Background(), msgBytes, "application/didcomm-plain+json")
	if err == nil {
		t.Error("expected error for unknown message type")
	}
}

func TestAgent_RegisterProtocol(t *testing.T) {
	agent, _ := New()

	agent.RegisterProtocol("https://example.com/custom/1.0", "sender", "receiver")

	// Verify by querying discover features
	// (the protocol should be in the registry)
}

func TestAgent_BuiltInHandlers(t *testing.T) {
	agent, _ := New()

	// Verify trust ping handler exists
	agent.handlersMu.RLock()
	_, hasPing := agent.handlers[trustping.TypePing]
	agent.handlersMu.RUnlock()

	if !hasPing {
		t.Error("trust ping handler not registered")
	}
}

// TestAgent_Send tests the Send method with a mock server.
func TestAgent_Send(t *testing.T) {
	// Set up a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and parse the incoming message
		body, _ := io.ReadAll(r.Body)

		// Parse to get the message ID for response
		result, err := didcomm.Unpack(context.Background(), body, didcomm.UnpackOptions{})
		if err != nil {
			// If we can't unpack (encrypted), return 202 Accepted
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// Create a response
		response := message.New(
			message.WithType("https://example.com/test-response"),
			message.WithThreadID(result.Message.ThreadID()),
		)
		responseBytes, _ := response.MarshalJSON()
		w.Header().Set("Content-Type", didcomm.MediaTypePlaintext)
		w.WriteHeader(http.StatusOK)
		w.Write(responseBytes)
	}))
	defer server.Close()

	// Set up resolvers
	endpointResolver := newMockEndpointResolver()
	endpointResolver.endpoints["did:example:bob"] = server.URL

	keyResolver := newMockKeyResolver()

	// Create agent
	agent, err := New(
		WithDID("did:example:alice"),
		WithEndpointResolver(endpointResolver),
		WithKeyResolver(keyResolver),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create message
	msg := message.New(
		message.WithType("https://example.com/test"),
		message.WithBody(map[string]any{"hello": "world"}),
	)

	// Send message
	response, err := agent.Send(context.Background(), "did:example:bob", msg)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if response == nil {
		t.Fatal("expected response, got nil")
	}

	if response.Type != "https://example.com/test-response" {
		t.Errorf("response.Type = %v, want https://example.com/test-response", response.Type)
	}
}

// TestAgent_Send_NoResolver tests Send without endpoint resolver.
func TestAgent_Send_NoResolver(t *testing.T) {
	agent, _ := New(WithDID("did:example:alice"))

	msg := message.New(message.WithType("https://example.com/test"))

	_, err := agent.Send(context.Background(), "did:example:bob", msg)
	if err != ErrNoResolver {
		t.Errorf("expected ErrNoResolver, got %v", err)
	}
}

// TestAgent_Send_NoEndpoint tests Send when endpoint resolution fails.
func TestAgent_Send_NoEndpoint(t *testing.T) {
	endpointResolver := newMockEndpointResolver()
	// Don't add any endpoints

	agent, _ := New(
		WithDID("did:example:alice"),
		WithEndpointResolver(endpointResolver),
	)

	msg := message.New(message.WithType("https://example.com/test"))

	_, err := agent.Send(context.Background(), "did:example:bob", msg)
	if err == nil {
		t.Error("expected error when endpoint not found")
	}
}

// TestAgent_Send_WithEncryption tests Send with encryption enabled.
func TestAgent_Send_WithEncryption(t *testing.T) {
	// Generate key pairs for Bob
	_, bobPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	// Set up mock server that accepts encrypted messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just accept the message
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Set up resolvers
	endpointResolver := newMockEndpointResolver()
	endpointResolver.endpoints["did:example:bob"] = server.URL

	keyResolver := newMockKeyResolver()
	keyResolver.agreementKeys["did:example:bob"] = []jwk.Key{bobPublicKey}

	// Create agent
	agent, _ := New(
		WithDID("did:example:alice"),
		WithEndpointResolver(endpointResolver),
		WithKeyResolver(keyResolver),
	)

	msg := message.New(
		message.WithType("https://example.com/test"),
		message.WithBody(map[string]any{"secret": "data"}),
	)

	// Send - should encrypt to bob's key
	_, err := agent.Send(context.Background(), "did:example:bob", msg)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

// TestAgent_HTTPHandler tests the HTTP handler functionality.
func TestAgent_HTTPHandler(t *testing.T) {
	agent, _ := New(WithDID("did:example:alice"))

	handler := agent.HTTPHandler()
	if handler == nil {
		t.Fatal("HTTPHandler() returned nil")
	}

	// Create a test request with a ping message
	ping, _ := trustping.NewPing("did:example:bob", "did:example:alice")
	pingBytes, _ := ping.MarshalJSON()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(pingBytes))
	req.Header.Set("Content-Type", didcomm.MediaTypePlaintext)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should get a ping response
	if rr.Code != http.StatusOK {
		t.Errorf("HTTPHandler response code = %d, want %d", rr.Code, http.StatusOK)
	}

	// Parse the response
	var response message.Message
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Type != trustping.TypePingResponse {
		t.Errorf("response.Type = %v, want %v", response.Type, trustping.TypePingResponse)
	}
}

// TestAgent_HTTPHandler_MethodNotAllowed tests HTTP handler with wrong method.
func TestAgent_HTTPHandler_MethodNotAllowed(t *testing.T) {
	agent, _ := New()
	handler := agent.HTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("response code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestAgent_SendTrustPing tests the SendTrustPing convenience method.
func TestAgent_SendTrustPing(t *testing.T) {
	// Set up mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the ping and respond with ping response
		body, _ := io.ReadAll(r.Body)
		result, _ := didcomm.Unpack(context.Background(), body, didcomm.UnpackOptions{})

		response, _ := trustping.HandlePing(result.Message)
		responseBytes, _ := response.MarshalJSON()

		w.Header().Set("Content-Type", didcomm.MediaTypePlaintext)
		w.WriteHeader(http.StatusOK)
		w.Write(responseBytes)
	}))
	defer server.Close()

	endpointResolver := newMockEndpointResolver()
	endpointResolver.endpoints["did:example:bob"] = server.URL

	agent, _ := New(
		WithDID("did:example:alice"),
		WithEndpointResolver(endpointResolver),
	)

	response, err := agent.SendTrustPing(context.Background(), "did:example:bob", true)
	if err != nil {
		t.Fatalf("SendTrustPing() error = %v", err)
	}

	if response == nil {
		t.Fatal("expected response")
	}

	if response.Type != trustping.TypePingResponse {
		t.Errorf("response.Type = %v, want %v", response.Type, trustping.TypePingResponse)
	}
}

// TestAgent_DiscoverFeatures tests the DiscoverFeatures convenience method.
func TestAgent_DiscoverFeatures(t *testing.T) {
	// Set up mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		result, _ := didcomm.Unpack(context.Background(), body, didcomm.UnpackOptions{})

		// Create a mock response with protocols
		response := message.New(
			message.WithType(discoverfeatures.TypeDisclose),
			message.WithThreadID(result.Message.ThreadID()),
			message.WithBody(map[string]any{
				"disclosures": []map[string]any{
					{
						"feature-type": "protocol",
						"id":           trustping.ProtocolURI,
					},
				},
			}),
		)
		responseBytes, _ := response.MarshalJSON()

		w.Header().Set("Content-Type", didcomm.MediaTypePlaintext)
		w.WriteHeader(http.StatusOK)
		w.Write(responseBytes)
	}))
	defer server.Close()

	endpointResolver := newMockEndpointResolver()
	endpointResolver.endpoints["did:example:bob"] = server.URL

	agent, _ := New(
		WithDID("did:example:alice"),
		WithEndpointResolver(endpointResolver),
	)

	disclosures, err := agent.DiscoverFeatures(context.Background(), "did:example:bob", "https://didcomm.org/*")
	if err != nil {
		t.Fatalf("DiscoverFeatures() error = %v", err)
	}

	if disclosures == nil {
		t.Fatal("expected disclosures")
	}

	if len(disclosures.Disclosures) == 0 {
		t.Error("expected at least one disclosure")
	}
}

// TestAgent_ProcessMessage_WithEncryptedResponse tests response encryption.
func TestAgent_ProcessMessage_WithEncryptedResponse(t *testing.T) {
	_, bobPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	keyResolver := newMockKeyResolver()
	keyResolver.agreementKeys["did:example:bob"] = []jwk.Key{bobPublicKey}

	agent, _ := New(
		WithDID("did:example:alice"),
		WithKeyResolver(keyResolver),
	)

	// Create a ping message from bob
	ping, _ := trustping.NewPing("did:example:bob", "did:example:alice")
	pingBytes, _ := ping.MarshalJSON()

	// Process the message - response should be encrypted to bob
	responseBytes, mediaType, err := agent.ProcessMessage(context.Background(), pingBytes, didcomm.MediaTypePlaintext)
	if err != nil {
		t.Fatalf("ProcessMessage() error = %v", err)
	}

	if responseBytes == nil {
		t.Fatal("expected response")
	}

	// Response should be encrypted (since we have bob's key)
	if mediaType != didcomm.MediaTypeEncrypted {
		t.Errorf("mediaType = %v, want %v", mediaType, didcomm.MediaTypeEncrypted)
	}
}

// TestAgentKeyStore_ListKeyIDs tests the agentKeyStore adapter.
func TestAgentKeyStore_ListKeyIDs(t *testing.T) {
	// Test with a store that supports listing
	mockStore := newMockKeyStore()
	mockStore.keyList = []string{"key-1", "key-2"}

	adapter := &agentKeyStore{store: mockStore}

	ids, err := adapter.ListKeyIDs(context.Background())
	if err != nil {
		t.Fatalf("ListKeyIDs() error = %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("len(ids) = %d, want 2", len(ids))
	}
}

// TestAgentKeyStore_ListKeyIDs_NotSupported tests agentKeyStore when underlying store doesn't support listing.
func TestAgentKeyStore_ListKeyIDs_NotSupported(t *testing.T) {
	// Create a minimal store that doesn't support listing
	store := &minimalKeyStore{}
	adapter := &agentKeyStore{store: store}

	ids, err := adapter.ListKeyIDs(context.Background())
	if err != nil {
		t.Fatalf("ListKeyIDs() error = %v", err)
	}

	// Should return empty list when not supported
	if ids != nil && len(ids) != 0 {
		t.Errorf("expected nil or empty list, got %v", ids)
	}
}

// minimalKeyStore implements KeyStore without ListKeyIDs.
type minimalKeyStore struct{}

func (s *minimalKeyStore) GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error) {
	return nil, ErrNoPrivateKey
}

// TestAgent_WithAllOptions tests agent creation with all options.
func TestAgent_WithAllOptions(t *testing.T) {
	keyStore := newMockKeyStore()
	keyResolver := newMockKeyResolver()
	endpointResolver := newMockEndpointResolver()

	agent, err := New(
		WithDID("did:example:alice"),
		WithKeyStore(keyStore),
		WithKeyResolver(keyResolver),
		WithEndpointResolver(endpointResolver),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if agent.DID() != "did:example:alice" {
		t.Errorf("DID() = %v, want did:example:alice", agent.DID())
	}

	if agent.keyStore == nil {
		t.Error("keyStore not set")
	}

	if agent.keyResolver == nil {
		t.Error("keyResolver not set")
	}

	if agent.endpointResolver == nil {
		t.Error("endpointResolver not set")
	}
}

// TestAgent_HandleDiscoverFeatures tests the discover features handler.
func TestAgent_HandleDiscoverFeatures(t *testing.T) {
	agent, _ := New(WithDID("did:example:alice"))

	// Register a custom protocol
	agent.RegisterProtocol("https://example.com/custom/1.0", "sender", "receiver")

	// Create a discover features query
	query, _ := discoverfeatures.NewQuery("did:example:bob", "did:example:alice",
		discoverfeatures.QueryProtocols("*"))
	queryBytes, _ := query.MarshalJSON()

	// Process
	responseBytes, _, err := agent.ProcessMessage(context.Background(), queryBytes, didcomm.MediaTypePlaintext)
	if err != nil {
		t.Fatalf("ProcessMessage() error = %v", err)
	}

	if responseBytes == nil {
		t.Fatal("expected response")
	}

	// Parse response
	response, err := message.Parse(responseBytes)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Type != discoverfeatures.TypeDisclose {
		t.Errorf("response.Type = %v, want %v", response.Type, discoverfeatures.TypeDisclose)
	}

	// Verify our custom protocol is disclosed
	body, _ := discoverfeatures.GetDiscloseBody(response)
	found := false
	for _, d := range body.Disclosures {
		if d.ID == "https://example.com/custom/1.0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("custom protocol not found in disclosures")
	}
}
