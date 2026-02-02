//go:build didcomm && vc20

package agent

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"vc/pkg/didcomm/message"
	"vc/pkg/didcomm/protocol/trustping"
)

// mockKeyStore implements KeyStore for testing.
type mockKeyStore struct {
	keys map[string]jwk.Key
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
