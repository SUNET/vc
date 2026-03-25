package presentproof

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

// CredentialFinder provides access to stored credentials for presentation.
type CredentialFinder interface {
	// FindCredentials finds credentials matching a presentation definition.
	// Returns the matching credentials as JSON.
	FindCredentials(ctx context.Context, presentationDef json.RawMessage) ([]json.RawMessage, error)
}

// PresentationBuilder builds verifiable presentations from credentials.
type PresentationBuilder interface {
	// BuildPresentation creates a VP from credentials for a presentation definition.
	BuildPresentation(ctx context.Context, credentials []json.RawMessage, presentationDef json.RawMessage, holderDID string) (json.RawMessage, error)
}

// PresentationVerifier verifies received presentations.
type PresentationVerifier interface {
	// VerifyPresentation verifies a VP against a presentation definition.
	// Returns the extracted credentials if valid.
	VerifyPresentation(ctx context.Context, vp json.RawMessage, presentationDef json.RawMessage) ([]json.RawMessage, error)
}

// Handler handles present-proof protocol messages.
type Handler struct {
	holderDID    string
	store        CredentialFinder
	builder      PresentationBuilder
	verifier     PresentationVerifier
	onRequest    func(ctx context.Context, request *RequestPresentation, msg *message.Message) (*message.Message, error)
	onPresentation func(ctx context.Context, presentation *Presentation, msg *message.Message) (*message.Message, error)
}

// HandlerOption configures the handler.
type HandlerOption func(*Handler)

// WithCredentialStore sets the credential store for finding matching credentials.
func WithCredentialStore(store CredentialFinder) HandlerOption {
	return func(h *Handler) {
		h.store = store
	}
}

// WithPresentationBuilder sets the builder for creating presentations.
func WithPresentationBuilder(builder PresentationBuilder) HandlerOption {
	return func(h *Handler) {
		h.builder = builder
	}
}

// WithPresentationVerifier sets the verifier for incoming presentations.
func WithPresentationVerifier(verifier PresentationVerifier) HandlerOption {
	return func(h *Handler) {
		h.verifier = verifier
	}
}

// WithRequestHandler sets a custom handler for presentation requests.
// If not set, the default auto-respond behavior is used.
func WithRequestHandler(handler func(ctx context.Context, request *RequestPresentation, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onRequest = handler
	}
}

// WithPresentationHandler sets a custom handler for received presentations.
func WithPresentationHandler(handler func(ctx context.Context, presentation *Presentation, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onPresentation = handler
	}
}

// NewHandler creates a new present-proof protocol handler.
func NewHandler(holderDID string, opts ...HandlerOption) *Handler {
	h := &Handler{
		holderDID: holderDID,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// MessageTypes returns the message types this handler supports.
func (h *Handler) MessageTypes() []string {
	return []string{
		TypeRequestPresentation,
		TypePresentation,
		TypeProposePresentation,
		TypePresentationAck,
	}
}

// Handle processes an incoming present-proof message.
func (h *Handler) Handle(ctx context.Context, msg *message.Message) (*message.Message, error) {
	switch msg.Type {
	case TypeRequestPresentation:
		return h.handleRequest(ctx, msg)
	case TypePresentation:
		return h.handlePresentation(ctx, msg)
	case TypeProposePresentation:
		return h.handleProposal(ctx, msg)
	case TypePresentationAck:
		return nil, nil // Acks don't require a response
	default:
		return nil, fmt.Errorf("unsupported message type: %s", msg.Type)
	}
}

// handleRequest processes a presentation request.
func (h *Handler) handleRequest(ctx context.Context, msg *message.Message) (*message.Message, error) {
	request, err := ParseRequestPresentation(msg)
	if err != nil {
		return nil, err
	}

	// Use custom handler if set
	if h.onRequest != nil {
		return h.onRequest(ctx, request, msg)
	}

	// Default auto-respond behavior
	return h.autoRespond(ctx, request, msg)
}

// autoRespond automatically responds to a presentation request.
func (h *Handler) autoRespond(ctx context.Context, request *RequestPresentation, msg *message.Message) (*message.Message, error) {
	if h.store == nil || h.builder == nil {
		return nil, fmt.Errorf("credential store and presentation builder required for auto-respond")
	}

	// Get the presentation definition
	presentationDef, err := request.GetPresentationDefinition()
	if err != nil {
		return nil, fmt.Errorf("failed to get presentation definition: %w", err)
	}

	// Find matching credentials
	credentials, err := h.store.FindCredentials(ctx, presentationDef)
	if err != nil {
		return nil, fmt.Errorf("failed to find credentials: %w", err)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials match the presentation definition")
	}

	// Build the presentation
	vp, err := h.builder.BuildPresentation(ctx, credentials, presentationDef, h.holderDID)
	if err != nil {
		return nil, fmt.Errorf("failed to build presentation: %w", err)
	}

	// Create and return the presentation message
	return NewPresentation(msg, vp)
}

// handlePresentation processes a received presentation.
func (h *Handler) handlePresentation(ctx context.Context, msg *message.Message) (*message.Message, error) {
	presentation, err := ParsePresentation(msg)
	if err != nil {
		return nil, err
	}

	// Use custom handler if set
	if h.onPresentation != nil {
		return h.onPresentation(ctx, presentation, msg)
	}

	// Default verification behavior
	if h.verifier != nil {
		vp, err := presentation.GetVerifiablePresentation()
		if err != nil {
			return nil, err
		}

		// Verify the presentation (we need the original request's presentation definition)
		// For now, just acknowledge receipt
		_ = vp
	}

	return nil, nil // No response needed for presentation
}

// handleProposal processes a presentation proposal.
func (h *Handler) handleProposal(ctx context.Context, msg *message.Message) (*message.Message, error) {
	// Proposals typically require manual handling
	// For now, return nil to indicate no automatic response
	return nil, nil
}

// RequestPresentation sends a presentation request to a holder.
// This is a helper for verifiers initiating the protocol.
func (h *Handler) RequestPresentation(verifierDID, holderDID string, presentationDef json.RawMessage, opts ...RequestOption) (*message.Message, error) {
	return NewRequestPresentation(verifierDID, holderDID, presentationDef, opts...)
}
