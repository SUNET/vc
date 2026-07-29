package agent

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/SUNET/vc/pkg/didcomm"
	"github.com/SUNET/vc/pkg/didcomm/message"
	"github.com/SUNET/vc/pkg/didcomm/protocol/discoverfeatures"
	"github.com/SUNET/vc/pkg/didcomm/protocol/trustping"
	"github.com/SUNET/vc/pkg/didcomm/transport"
)

// KeyStore provides access to private keys.
type KeyStore interface {
	// GetPrivateKey returns the private key for the given key ID.
	GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error)
}

// EndpointResolver resolves DID service endpoints.
type EndpointResolver interface {
	// ResolveEndpoint returns the DIDComm service endpoint for a DID.
	ResolveEndpoint(ctx context.Context, did string) (string, error)
}

// KeyResolver resolves public keys for a DID.
type KeyResolver interface {
	// ResolveKeyAgreement returns key agreement keys for encryption.
	ResolveKeyAgreement(ctx context.Context, did string) ([]jwk.Key, error)

	// ResolveVerification returns verification keys for signature verification.
	ResolveVerification(ctx context.Context, did string) ([]jwk.Key, error)
}

// MessageHandler handles incoming DIDComm messages.
type MessageHandler func(ctx context.Context, msg *message.Message) (*message.Message, error)

// Agent is a high-level DIDComm messaging agent.
type Agent struct {
	did              string
	keyStore         KeyStore
	keyResolver      KeyResolver
	endpointResolver EndpointResolver
	httpClient       *transport.HTTPClient

	handlers   map[string]MessageHandler
	handlersMu sync.RWMutex

	protocols *discoverfeatures.ProtocolRegistry
}

// Option configures the agent.
type Option func(*Agent)

// WithDID sets the agent's DID.
func WithDID(did string) Option {
	return func(a *Agent) {
		a.did = did
	}
}

// WithKeyStore sets the key store for private key access.
func WithKeyStore(ks KeyStore) Option {
	return func(a *Agent) {
		a.keyStore = ks
	}
}

// WithKeyResolver sets the key resolver for public keys.
func WithKeyResolver(kr KeyResolver) Option {
	return func(a *Agent) {
		a.keyResolver = kr
	}
}

// WithEndpointResolver sets the endpoint resolver.
func WithEndpointResolver(er EndpointResolver) Option {
	return func(a *Agent) {
		a.endpointResolver = er
	}
}

// New creates a new DIDComm agent.
func New(opts ...Option) (*Agent, error) {
	a := &Agent{
		handlers:   make(map[string]MessageHandler),
		protocols:  discoverfeatures.NewProtocolRegistry(),
		httpClient: transport.NewHTTPClient(),
	}

	for _, opt := range opts {
		opt(a)
	}

	// Register built-in protocol handlers
	a.registerBuiltInHandlers()

	return a, nil
}

// DID returns the agent's DID.
func (a *Agent) DID() string {
	return a.did
}

// RegisterHandler registers a handler for a message type.
func (a *Agent) RegisterHandler(messageType string, handler MessageHandler) {
	a.handlersMu.Lock()
	defer a.handlersMu.Unlock()
	a.handlers[messageType] = handler
}

// RegisterProtocol registers a protocol for feature discovery.
func (a *Agent) RegisterProtocol(uri string, roles ...string) {
	a.protocols.RegisterProtocol(uri, roles...)
}

// registerBuiltInHandlers registers handlers for built-in protocols.
func (a *Agent) registerBuiltInHandlers() {
	// Trust Ping
	a.RegisterHandler(trustping.TypePing, a.handleTrustPing)
	a.protocols.RegisterProtocol(trustping.ProtocolURI, "sender", "receiver")

	// Discover Features
	a.RegisterHandler(discoverfeatures.TypeQueries, a.handleDiscoverFeatures)
	a.protocols.RegisterProtocol(discoverfeatures.ProtocolURI, "requester", "responder")
}

// handleTrustPing handles incoming trust ping messages.
func (a *Agent) handleTrustPing(ctx context.Context, msg *message.Message) (*message.Message, error) {
	return trustping.HandlePing(msg)
}

// handleDiscoverFeatures handles discover-features queries.
func (a *Agent) handleDiscoverFeatures(ctx context.Context, msg *message.Message) (*message.Message, error) {
	return a.protocols.HandleQuery(msg)
}

// Send sends a message to the recipient.
func (a *Agent) Send(ctx context.Context, to string, msg *message.Message) (*message.Message, error) {
	if a.endpointResolver == nil {
		return nil, ErrNoResolver
	}

	// Get recipient endpoint
	endpoint, err := a.endpointResolver.ResolveEndpoint(ctx, to)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoEndpoint, err)
	}

	// Set message addressing
	msg.From = a.did
	msg.To = []string{to}

	// Pack the message
	packed, err := a.packMessage(ctx, msg, to)
	if err != nil {
		return nil, err
	}

	// Send
	responseBytes, err := a.httpClient.SendMessage(ctx, endpoint, packed.Message, packed.MediaType)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// If no response, return nil
	if responseBytes == nil {
		return nil, nil
	}

	// Unpack response
	result, err := a.unpackMessage(ctx, responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	return result.Message, nil
}

// packMessage packs a message for sending.
func (a *Agent) packMessage(ctx context.Context, msg *message.Message, to string) (*didcomm.PackResult, error) {
	// If we have a key resolver, try to encrypt
	if a.keyResolver != nil {
		recipientKeys, err := a.keyResolver.ResolveKeyAgreement(ctx, to)
		if err == nil && len(recipientKeys) > 0 {
			return didcomm.PackAnoncrypt(ctx, msg, recipientKeys)
		}
	}

	// Fall back to plaintext
	return didcomm.PackPlaintext(msg)
}

// unpackMessage unpacks a received message.
func (a *Agent) unpackMessage(ctx context.Context, data []byte) (*didcomm.UnpackResult, error) {
	opts := didcomm.UnpackOptions{}

	if a.keyStore != nil {
		opts.KeyStore = &agentKeyStore{store: a.keyStore}
	}

	return didcomm.Unpack(ctx, data, opts)
}

// agentKeyStore adapts KeyStore to crypto.KeyStore.
type agentKeyStore struct {
	store KeyStore
}

func (ks *agentKeyStore) GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error) {
	return ks.store.GetPrivateKey(ctx, kid)
}

func (ks *agentKeyStore) ListKeyIDs(ctx context.Context) ([]string, error) {
	// If the underlying store supports listing, delegate to it
	if lister, ok := ks.store.(interface {
		ListKeyIDs(context.Context) ([]string, error)
	}); ok {
		return lister.ListKeyIDs(ctx)
	}
	// Otherwise return empty list
	return nil, nil
}

// ProcessMessage processes an incoming message.
func (a *Agent) ProcessMessage(ctx context.Context, data []byte, mediaType string) ([]byte, string, error) {
	// Unpack the message
	result, err := a.unpackMessage(ctx, data)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrProcessingFailed, err)
	}

	// Find handler
	a.handlersMu.RLock()
	handler, exists := a.handlers[result.Message.Type]
	a.handlersMu.RUnlock()

	if !exists {
		return nil, "", fmt.Errorf("%w: %s", ErrNoHandler, result.Message.Type)
	}

	// Process
	response, err := handler(ctx, result.Message)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrProcessingFailed, err)
	}

	// If no response, return nil
	if response == nil {
		return nil, "", nil
	}

	// Pack response
	var packed *didcomm.PackResult
	if result.Message.From != "" && a.keyResolver != nil {
		recipientKeys, err := a.keyResolver.ResolveKeyAgreement(ctx, result.Message.From)
		if err == nil && len(recipientKeys) > 0 {
			packed, err = didcomm.PackAnoncrypt(ctx, response, recipientKeys)
			if err == nil {
				return packed.Message, packed.MediaType, nil
			}
		}
	}

	// Fall back to plaintext
	packed, err = didcomm.PackPlaintext(response)
	if err != nil {
		return nil, "", err
	}

	return packed.Message, packed.MediaType, nil
}

// HTTPHandler returns an HTTP handler for receiving messages.
func (a *Agent) HTTPHandler() http.Handler {
	return transport.NewHTTPHandler(a)
}

// SendTrustPing sends a trust ping to the recipient.
func (a *Agent) SendTrustPing(ctx context.Context, to string, responseRequested bool) (*message.Message, error) {
	ping, err := trustping.NewPing(a.did, to, trustping.WithResponseRequested(responseRequested))
	if err != nil {
		return nil, err
	}
	return a.Send(ctx, to, ping)
}

// DiscoverFeatures queries the recipient for supported features.
func (a *Agent) DiscoverFeatures(ctx context.Context, to string, pattern string) (*discoverfeatures.DiscloseBody, error) {
	query, err := discoverfeatures.NewQuery(a.did, to, discoverfeatures.QueryProtocols(pattern))
	if err != nil {
		return nil, err
	}

	response, err := a.Send(ctx, to, query)
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	return discoverfeatures.GetDiscloseBody(response)
}
