# Aries Issue Credential 3.0 Implementation Plan

## Overview

Implement the [Aries Issue Credential 3.0](https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md) protocol for DIDComm 2.1 in `pkg/didcomm/protocol/issuecredential/`.

**Protocol URI:** `https://didcomm.org/issue-credential/3.0`

## Protocol Flow

```
┌──────────┐                              ┌──────────┐
│  Holder  │                              │  Issuer  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  1. propose-credential (optional)       │
     │────────────────────────────────────────>│
     │                                         │
     │  2. offer-credential                    │
     │<────────────────────────────────────────│
     │                                         │
     │  3. request-credential                  │
     │────────────────────────────────────────>│
     │                                         │
     │  4. issue-credential                    │
     │<────────────────────────────────────────│
     │                                         │
     │  5. ack (optional)                      │
     │────────────────────────────────────────>│
     │                                         │
```

### Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `propose-credential` | Holder → Issuer | Holder proposes what credential they want |
| `offer-credential` | Issuer → Holder | Issuer offers a credential with preview |
| `request-credential` | Holder → Issuer | Holder accepts offer and requests issuance |
| `issue-credential` | Issuer → Holder | Issuer delivers the credential |
| `ack` | Holder → Issuer | Holder confirms receipt |
| `problem-report` | Either | Error/rejection |

### Credential Formats (Attachments)

| Format ID | Description |
|-----------|-------------|
| `aries/ld-proof-vc-detail@v2.0` | W3C VC Data Integrity detail (for offer/request) |
| `aries/ld-proof-vc@v2.0` | W3C VC Data Integrity (for issue) |
| `dif/credential-manifest@v1.0` | DIF Credential Manifest |
| `jwt/credential-offer@v1.0` | JWT VC offer |
| `jwt/vc@v1.0` | JWT VC (for issue) |

---

## Implementation Structure

```
pkg/didcomm/protocol/issuecredential/
├── issuecredential.go    # Types, constants, message constructors
├── handler.go            # Protocol handler with issuer/holder modes
├── state.go              # State machine for conversation tracking
└── issuecredential_test.go
```

---

## Phase 1: Core Types and Messages

### 1.1 Constants and Types (`issuecredential.go`)

```go
//go:build didcomm && vc20

package issuecredential

const (
    ProtocolURI              = "https://didcomm.org/issue-credential/3.0"
    TypeProposeCredential    = ProtocolURI + "/propose-credential"
    TypeOfferCredential      = ProtocolURI + "/offer-credential"
    TypeRequestCredential    = ProtocolURI + "/request-credential"
    TypeIssueCredential      = ProtocolURI + "/issue-credential"
    TypeCredentialAck        = ProtocolURI + "/ack"
    TypeCredentialProblem    = ProtocolURI + "/problem-report"
    
    // Attachment formats
    FormatLDProofVCDetail    = "aries/ld-proof-vc-detail@v2.0"
    FormatLDProofVC          = "aries/ld-proof-vc@v2.0"
    FormatCredentialManifest = "dif/credential-manifest@v1.0"
    FormatJWTOffer           = "jwt/credential-offer@v1.0"
    FormatJWTVC              = "jwt/vc@v1.0"
    
    // Goal codes
    GoalCodeIssueVC          = "aries.vc.issue"
)
```

### 1.2 Message Body Types

```go
// ProposeCredential is sent by holder to initiate issuance.
type ProposeCredential struct {
    GoalCode       string       `json:"goal_code,omitempty"`
    Comment        string       `json:"comment,omitempty"`
    CredentialPreview *Preview  `json:"credential_preview,omitempty"`
    FiltersAttach  []Attachment `json:"filters~attach,omitempty"`
}

// OfferCredential is sent by issuer with credential details.
type OfferCredential struct {
    GoalCode          string       `json:"goal_code,omitempty"`
    Comment           string       `json:"comment,omitempty"`
    ReplacementID     string       `json:"replacement_id,omitempty"`
    CredentialPreview *Preview     `json:"credential_preview,omitempty"`
    OffersAttach      []Attachment `json:"offers~attach"`
}

// RequestCredential is sent by holder to accept an offer.
type RequestCredential struct {
    GoalCode       string       `json:"goal_code,omitempty"`
    Comment        string       `json:"comment,omitempty"`
    RequestsAttach []Attachment `json:"requests~attach"`
}

// IssueCredential delivers the credential to holder.
type IssueCredential struct {
    GoalCode           string       `json:"goal_code,omitempty"`
    Comment            string       `json:"comment,omitempty"`
    ReplacementID      string       `json:"replacement_id,omitempty"`
    CredentialsAttach  []Attachment `json:"credentials~attach"`
}

// Preview describes the credential before issuance.
type Preview struct {
    Type       string           `json:"@type"`
    Attributes []PreviewAttribute `json:"attributes"`
}

// PreviewAttribute is a claim in the credential preview.
type PreviewAttribute struct {
    Name     string `json:"name"`
    MimeType string `json:"mime-type,omitempty"`
    Value    string `json:"value"`
}

// Attachment carries credential data.
type Attachment struct {
    ID        string         `json:"@id"`
    MediaType string         `json:"media_type,omitempty"`
    Format    string         `json:"format,omitempty"`
    Data      AttachmentData `json:"data"`
}

type AttachmentData struct {
    JSON   json.RawMessage `json:"json,omitempty"`
    Base64 string          `json:"base64,omitempty"`
    Links  []string        `json:"links,omitempty"`
    JWS    string          `json:"jws,omitempty"`
}
```

### 1.3 Message Constructors

```go
// NewOfferCredential creates an offer message.
func NewOfferCredential(from, to string, preview *Preview, credentialDetail json.RawMessage, format string, opts ...OfferOption) (*message.Message, error)

// NewRequestCredential creates a request accepting an offer.
func NewRequestCredential(offer *message.Message, holderBinding json.RawMessage, opts ...RequestOption) (*message.Message, error)

// NewIssueCredential creates the credential delivery message.
func NewIssueCredential(request *message.Message, credential json.RawMessage, format string, opts ...IssueOption) (*message.Message, error)

// NewProposeCredential creates a proposal from holder.
func NewProposeCredential(from, to string, filter json.RawMessage, opts ...ProposeOption) (*message.Message, error)

// NewCredentialAck creates an acknowledgment.
func NewCredentialAck(issue *message.Message) (*message.Message, error)

// Parsers
func ParseOfferCredential(msg *message.Message) (*OfferCredential, error)
func ParseRequestCredential(msg *message.Message) (*RequestCredential, error)
func ParseIssueCredential(msg *message.Message) (*IssueCredential, error)
func ParseProposeCredential(msg *message.Message) (*ProposeCredential, error)
```

---

## Phase 2: Handler Implementation

### 2.1 Interfaces (`handler.go`)

```go
// CredentialIssuer creates and signs credentials.
type CredentialIssuer interface {
    // IssueCredential creates a signed credential from a request.
    // Returns the credential as JSON (W3C VC or JWT).
    IssueCredential(ctx context.Context, request *RequestCredential, holderDID string) (json.RawMessage, string, error)
}

// CredentialStore stores received credentials.
type CredentialStore interface {
    // StoreCredential saves a received credential.
    StoreCredential(ctx context.Context, credential json.RawMessage, format string, issuerDID string) error
}

// OfferEvaluator decides whether to accept a credential offer.
type OfferEvaluator interface {
    // EvaluateOffer decides if the offer should be accepted.
    // Returns holder binding data if accepted, error if rejected.
    EvaluateOffer(ctx context.Context, offer *OfferCredential, issuerDID string) (json.RawMessage, error)
}

// CredentialPreviewBuilder creates preview from credential request.
type CredentialPreviewBuilder interface {
    // BuildPreview creates a credential preview for an offer.
    BuildPreview(ctx context.Context, credentialType string, claims map[string]any) (*Preview, error)
}
```

### 2.2 Handler Structure

```go
// Handler handles issue-credential protocol messages.
type Handler struct {
    // DID for this agent
    agentDID string
    
    // Issuer mode dependencies
    issuer         CredentialIssuer
    previewBuilder CredentialPreviewBuilder
    
    // Holder mode dependencies  
    store          CredentialStore
    evaluator      OfferEvaluator
    
    // Custom handlers
    onOffer   func(ctx context.Context, offer *OfferCredential, msg *message.Message) (*message.Message, error)
    onRequest func(ctx context.Context, request *RequestCredential, msg *message.Message) (*message.Message, error)
    onIssue   func(ctx context.Context, issue *IssueCredential, msg *message.Message) (*message.Message, error)
    
    // State tracking
    conversations map[string]*ConversationState
}

// NewHandler creates a new issue-credential handler.
func NewHandler(agentDID string, opts ...HandlerOption) *Handler

// MessageTypes returns supported message types.
func (h *Handler) MessageTypes() []string

// Handle processes an incoming message.
func (h *Handler) Handle(ctx context.Context, msg *message.Message) (*message.Message, error)
```

### 2.3 Handler Options

```go
// Issuer mode
func WithCredentialIssuer(issuer CredentialIssuer) HandlerOption
func WithPreviewBuilder(builder CredentialPreviewBuilder) HandlerOption

// Holder mode
func WithCredentialStore(store CredentialStore) HandlerOption
func WithOfferEvaluator(evaluator OfferEvaluator) HandlerOption

// Custom handlers
func WithOfferHandler(handler func(...)) HandlerOption
func WithRequestHandler(handler func(...)) HandlerOption
func WithIssueHandler(handler func(...)) HandlerOption

// Auto-accept offers (for testing/automation)
func WithAutoAccept() HandlerOption
```

---

## Phase 3: State Machine

### 3.1 Conversation State (`state.go`)

```go
type State string

const (
    StateProposalSent     State = "proposal-sent"
    StateProposalReceived State = "proposal-received"
    StateOfferSent        State = "offer-sent"
    StateOfferReceived    State = "offer-received"
    StateRequestSent      State = "request-sent"
    StateRequestReceived  State = "request-received"
    StateCredentialIssued State = "credential-issued"
    StateCredentialReceived State = "credential-received"
    StateAckReceived      State = "ack-received"
    StateDone             State = "done"
    StateAbandoned        State = "abandoned"
)

type ConversationState struct {
    ThreadID     string
    State        State
    Role         Role // Issuer or Holder
    PeerDID      string
    LastOffer    *OfferCredential
    LastRequest  *RequestCredential
    Credential   json.RawMessage
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

// Valid state transitions
var validTransitions = map[State][]State{
    StateProposalSent:     {StateOfferReceived, StateAbandoned},
    StateProposalReceived: {StateOfferSent, StateAbandoned},
    StateOfferSent:        {StateRequestReceived, StateAbandoned},
    StateOfferReceived:    {StateRequestSent, StateAbandoned},
    StateRequestSent:      {StateCredentialReceived, StateAbandoned},
    StateRequestReceived:  {StateCredentialIssued, StateAbandoned},
    StateCredentialIssued: {StateAckReceived, StateDone},
    StateCredentialReceived: {StateDone},
}
```

---

## Phase 4: Integration with vc Project

### 4.1 W3C VC Data Integrity Integration

```go
// VC20CredentialIssuer implements CredentialIssuer using vc20 package.
type VC20CredentialIssuer struct {
    signer      vccrypto.VCSigner
    issuerDID   string
    cryptosuite string // "ecdsa-rdfc-2019" or "ecdsa-sd-2023"
}

func (i *VC20CredentialIssuer) IssueCredential(ctx context.Context, request *RequestCredential, holderDID string) (json.RawMessage, string, error) {
    // 1. Extract credential detail from request attachment
    // 2. Build W3C VC with credentialSubject.id = holderDID
    // 3. Sign using vc20/crypto
    // 4. Return signed credential JSON
}
```

### 4.2 SD-JWT VC Integration

```go
// SDJWTCredentialIssuer implements CredentialIssuer for SD-JWT VCs.
type SDJWTCredentialIssuer struct {
    signer    vccrypto.VCSigner
    issuerDID string
}
```

---

## Phase 5: Testing

### 5.1 Unit Tests

```go
func TestNewOfferCredential(t *testing.T)
func TestNewRequestCredential(t *testing.T)
func TestNewIssueCredential(t *testing.T)
func TestHandlerIssuerMode(t *testing.T)
func TestHandlerHolderMode(t *testing.T)
func TestStateTransitions(t *testing.T)
func TestRoundTrip(t *testing.T)
```

### 5.2 Integration Tests

- Test with present-proof (offer credential after successful verification)
- Test with WebSocket transport
- Test with out-of-band invitation containing credential offer

---

## Implementation Timeline

| Phase | Effort | Description |
|-------|--------|-------------|
| Phase 1 | 2-3h | Core types, constants, message constructors |
| Phase 2 | 3-4h | Handler with issuer/holder modes |
| Phase 3 | 1-2h | State machine for conversation tracking |
| Phase 4 | 2-3h | VC20 and SD-JWT issuer integrations |
| Phase 5 | 2h | Unit and integration tests |

**Total: ~10-14 hours**

---

## Dependencies

- `vc/pkg/didcomm/message` - Message types
- `vc/pkg/vc20/crypto` - W3C VC Data Integrity signing
- `vc/pkg/sdjwtvc` - SD-JWT VC signing (optional)

---

## References

- [Aries RFC 0453: Issue Credential v2](https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md)
- [DIDComm Messaging Spec](https://identity.foundation/didcomm-messaging/spec/v2.1/)
- [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [DIF Credential Manifest](https://identity.foundation/credential-manifest/)
