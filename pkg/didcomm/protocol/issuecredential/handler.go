package issuecredential

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

// CredentialIssuer creates and signs credentials.
type CredentialIssuer interface {
	// IssueCredential creates a signed credential from a request.
	// Returns the credential as JSON and the format identifier.
	IssueCredential(ctx context.Context, request *RequestCredential, holderDID string) (json.RawMessage, string, error)
}

// CredentialStorer stores received credentials.
type CredentialStorer interface {
	// StoreCredential saves a received credential.
	StoreCredential(ctx context.Context, credential json.RawMessage, format string, issuerDID string) error
}

// OfferEvaluator decides whether to accept a credential offer.
type OfferEvaluator interface {
	// EvaluateOffer decides if the offer should be accepted.
	// Returns holder binding data (e.g., DID key binding) if accepted.
	// Returns error if offer should be rejected.
	EvaluateOffer(ctx context.Context, offer *OfferCredential, issuerDID string) (json.RawMessage, error)
}

// CredentialPreviewBuilder creates preview from credential data.
type CredentialPreviewBuilder interface {
	// BuildPreview creates a credential preview for an offer.
	BuildPreview(ctx context.Context, credentialType string, claims map[string]any) (*Preview, error)
}

// Handler handles issue-credential protocol messages.
type Handler struct {
	agentDID string

	// Issuer mode dependencies
	issuer         CredentialIssuer
	previewBuilder CredentialPreviewBuilder

	// Holder mode dependencies
	store     CredentialStorer
	evaluator OfferEvaluator

	// Custom message handlers
	onProposal func(ctx context.Context, proposal *ProposeCredential, msg *message.Message) (*message.Message, error)
	onOffer    func(ctx context.Context, offer *OfferCredential, msg *message.Message) (*message.Message, error)
	onRequest  func(ctx context.Context, request *RequestCredential, msg *message.Message) (*message.Message, error)
	onIssue    func(ctx context.Context, issue *IssueCredential, msg *message.Message) (*message.Message, error)

	// Auto-accept mode (for testing)
	autoAccept bool

	// Thread state tracking
	mu            sync.RWMutex
	conversations map[string]*ConversationState
}

// ConversationState tracks the state of an issuance conversation.
type ConversationState struct {
	ThreadID    string
	State       State
	Role        Role
	PeerDID     string
	LastOffer   *OfferCredential
	LastRequest *RequestCredential
	Credential  json.RawMessage
}

// State represents the conversation state.
type State string

const (
	StateProposalSent       State = "proposal-sent"
	StateProposalReceived   State = "proposal-received"
	StateOfferSent          State = "offer-sent"
	StateOfferReceived      State = "offer-received"
	StateRequestSent        State = "request-sent"
	StateRequestReceived    State = "request-received"
	StateCredentialIssued   State = "credential-issued"   //#nosec G101 -- DIDComm protocol state, not a credential
	StateCredentialReceived State = "credential-received" //#nosec G101 -- DIDComm protocol state, not a credential
	StateAckReceived        State = "ack-received"
	StateDone               State = "done"
	StateAbandoned          State = "abandoned"
)

// Role indicates whether this agent is issuer or holder.
type Role string

const (
	RoleIssuer Role = "issuer"
	RoleHolder Role = "holder"
)

// HandlerOption configures the handler.
type HandlerOption func(*Handler)

// WithCredentialIssuer sets the credential issuer for issuer mode.
func WithCredentialIssuer(issuer CredentialIssuer) HandlerOption {
	return func(h *Handler) {
		h.issuer = issuer
	}
}

// WithPreviewBuilder sets the preview builder for issuer mode.
func WithPreviewBuilder(builder CredentialPreviewBuilder) HandlerOption {
	return func(h *Handler) {
		h.previewBuilder = builder
	}
}

// WithCredentialStore sets the credential store for holder mode.
func WithCredentialStore(store CredentialStorer) HandlerOption {
	return func(h *Handler) {
		h.store = store
	}
}

// WithOfferEvaluator sets the offer evaluator for holder mode.
func WithOfferEvaluator(evaluator OfferEvaluator) HandlerOption {
	return func(h *Handler) {
		h.evaluator = evaluator
	}
}

// WithProposalHandler sets a custom handler for proposals.
func WithProposalHandler(handler func(ctx context.Context, proposal *ProposeCredential, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onProposal = handler
	}
}

// WithOfferHandler sets a custom handler for offers.
func WithOfferHandler(handler func(ctx context.Context, offer *OfferCredential, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onOffer = handler
	}
}

// WithRequestHandler sets a custom handler for requests.
func WithRequestHandler(handler func(ctx context.Context, request *RequestCredential, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onRequest = handler
	}
}

// WithIssueHandler sets a custom handler for issue messages.
func WithIssueHandler(handler func(ctx context.Context, issue *IssueCredential, msg *message.Message) (*message.Message, error)) HandlerOption {
	return func(h *Handler) {
		h.onIssue = handler
	}
}

// WithAutoAccept enables auto-accept mode for testing.
// In this mode, offers are automatically accepted.
func WithAutoAccept() HandlerOption {
	return func(h *Handler) {
		h.autoAccept = true
	}
}

// NewHandler creates a new issue-credential protocol handler.
func NewHandler(agentDID string, opts ...HandlerOption) *Handler {
	h := &Handler{
		agentDID:      agentDID,
		conversations: make(map[string]*ConversationState),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// MessageTypes returns the message types this handler supports.
func (h *Handler) MessageTypes() []string {
	return []string{
		TypeProposeCredential,
		TypeOfferCredential,
		TypeRequestCredential,
		TypeIssueCredential,
		TypeCredentialAck,
	}
}

// Handle processes an incoming issue-credential message.
func (h *Handler) Handle(ctx context.Context, msg *message.Message) (*message.Message, error) {
	switch msg.Type {
	case TypeProposeCredential:
		return h.handleProposal(ctx, msg)
	case TypeOfferCredential:
		return h.handleOffer(ctx, msg)
	case TypeRequestCredential:
		return h.handleRequest(ctx, msg)
	case TypeIssueCredential:
		return h.handleIssue(ctx, msg)
	case TypeCredentialAck:
		return h.handleAck(ctx, msg)
	default:
		return nil, fmt.Errorf("unsupported message type: %s", msg.Type)
	}
}

// handleProposal processes a credential proposal (issuer receives from holder).
func (h *Handler) handleProposal(ctx context.Context, msg *message.Message) (*message.Message, error) {
	proposal, err := ParseProposeCredential(msg)
	if err != nil {
		return nil, err
	}

	// Track conversation
	h.updateState(msg.ID, StateProposalReceived, RoleIssuer, msg.From)

	// Use custom handler if set
	if h.onProposal != nil {
		return h.onProposal(ctx, proposal, msg)
	}

	// Default: return nil (no auto-response, issuer must explicitly offer)
	return nil, nil
}

// handleOffer processes a credential offer (holder receives from issuer).
func (h *Handler) handleOffer(ctx context.Context, msg *message.Message) (*message.Message, error) {
	offer, err := ParseOfferCredential(msg)
	if err != nil {
		return nil, err
	}

	// Track conversation
	threadID := msg.ThreadID()
	h.updateState(threadID, StateOfferReceived, RoleHolder, msg.From)
	h.mu.Lock()
	if state, exists := h.conversations[threadID]; exists {
		state.LastOffer = offer
	}
	h.mu.Unlock()

	// Use custom handler if set
	if h.onOffer != nil {
		return h.onOffer(ctx, offer, msg)
	}

	// Auto-accept mode or with evaluator
	if h.autoAccept || h.evaluator != nil {
		return h.autoRespondToOffer(ctx, offer, msg)
	}

	return nil, nil
}

// autoRespondToOffer automatically accepts an offer.
func (h *Handler) autoRespondToOffer(ctx context.Context, offer *OfferCredential, msg *message.Message) (*message.Message, error) {
	var holderBinding json.RawMessage

	// If we have an evaluator, use it
	if h.evaluator != nil {
		binding, err := h.evaluator.EvaluateOffer(ctx, offer, msg.From)
		if err != nil {
			return nil, fmt.Errorf("offer rejected: %w", err)
		}
		holderBinding = binding
	}

	// Create request
	request, err := NewRequestCredential(msg, holderBinding)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Update state
	threadID := msg.ThreadID()
	h.updateState(threadID, StateRequestSent, RoleHolder, msg.From)

	return request, nil
}

// handleRequest processes a credential request (issuer receives from holder).
func (h *Handler) handleRequest(ctx context.Context, msg *message.Message) (*message.Message, error) {
	request, err := ParseRequestCredential(msg)
	if err != nil {
		return nil, err
	}

	// Track conversation
	threadID := msg.ThreadID()
	h.updateState(threadID, StateRequestReceived, RoleIssuer, msg.From)
	h.mu.Lock()
	if state, exists := h.conversations[threadID]; exists {
		state.LastRequest = request
	}
	h.mu.Unlock()

	// Use custom handler if set
	if h.onRequest != nil {
		return h.onRequest(ctx, request, msg)
	}

	// Auto-issue if we have an issuer
	if h.issuer != nil {
		return h.autoIssue(ctx, request, msg)
	}

	return nil, nil
}

// autoIssue automatically issues a credential in response to a request.
func (h *Handler) autoIssue(ctx context.Context, request *RequestCredential, msg *message.Message) (*message.Message, error) {
	// Issue credential
	credential, format, err := h.issuer.IssueCredential(ctx, request, msg.From)
	if err != nil {
		return nil, fmt.Errorf("failed to issue credential: %w", err)
	}

	// Create issue message
	issue, err := NewIssueCredential(msg, credential, format)
	if err != nil {
		return nil, fmt.Errorf("failed to create issue message: %w", err)
	}

	// Update state
	threadID := msg.ThreadID()
	h.updateState(threadID, StateCredentialIssued, RoleIssuer, msg.From)

	return issue, nil
}

// handleIssue processes a credential issuance (holder receives from issuer).
func (h *Handler) handleIssue(ctx context.Context, msg *message.Message) (*message.Message, error) {
	issue, err := ParseIssueCredential(msg)
	if err != nil {
		return nil, err
	}

	// Track conversation
	threadID := msg.ThreadID()
	h.updateState(threadID, StateCredentialReceived, RoleHolder, msg.From)

	// Use custom handler if set
	if h.onIssue != nil {
		return h.onIssue(ctx, issue, msg)
	}

	// Store credential if we have a store
	if h.store != nil {
		credential, format, err := issue.GetCredential()
		if err != nil {
			return nil, fmt.Errorf("failed to extract credential: %w", err)
		}
		if err := h.store.StoreCredential(ctx, credential, format, msg.From); err != nil {
			return nil, fmt.Errorf("failed to store credential: %w", err)
		}
	}

	// Store credential in conversation state
	h.mu.Lock()
	if state, exists := h.conversations[threadID]; exists {
		cred, _, _ := issue.GetCredential()
		state.Credential = cred
	}
	h.mu.Unlock()

	// Send ack
	ack, err := NewCredentialAck(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ack: %w", err)
	}

	h.updateState(threadID, StateDone, RoleHolder, msg.From)

	return ack, nil
}

// handleAck processes an acknowledgment (issuer receives from holder).
func (h *Handler) handleAck(ctx context.Context, msg *message.Message) (*message.Message, error) {
	threadID := msg.ThreadID()
	h.updateState(threadID, StateAckReceived, RoleIssuer, msg.From)
	h.updateState(threadID, StateDone, RoleIssuer, msg.From)

	// Acks don't require a response
	return nil, nil
}

// updateState updates the conversation state.
func (h *Handler) updateState(threadID string, state State, role Role, peerDID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	conv, exists := h.conversations[threadID]
	if !exists {
		conv = &ConversationState{
			ThreadID: threadID,
			Role:     role,
			PeerDID:  peerDID,
		}
		h.conversations[threadID] = conv
	}
	conv.State = state
}

// GetConversation returns the state of a conversation.
func (h *Handler) GetConversation(threadID string) *ConversationState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conversations[threadID]
}

// CreateOffer creates a credential offer to send to a holder.
// This is used by issuers to initiate credential issuance.
func (h *Handler) CreateOffer(holderDID string, preview *Preview, credentialDetail json.RawMessage, format string, opts ...OfferOption) (*message.Message, error) {
	offer, err := NewOfferCredential(h.agentDID, holderDID, preview, credentialDetail, format, opts...)
	if err != nil {
		return nil, err
	}

	// Track as sent
	h.updateState(offer.ID, StateOfferSent, RoleIssuer, holderDID)

	return offer, nil
}

// CreateProposal creates a credential proposal to send to an issuer.
// This is used by holders to initiate credential issuance.
func (h *Handler) CreateProposal(issuerDID string, preview *Preview, filter json.RawMessage, opts ...ProposeOption) (*message.Message, error) {
	proposal, err := NewProposeCredential(h.agentDID, issuerDID, preview, filter, opts...)
	if err != nil {
		return nil, err
	}

	// Track as sent
	h.updateState(proposal.ID, StateProposalSent, RoleHolder, issuerDID)

	return proposal, nil
}
