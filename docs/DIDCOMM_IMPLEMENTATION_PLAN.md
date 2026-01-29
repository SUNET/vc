# DIDComm v2.1 Implementation Plan

## Project Overview

Implementation of DIDComm Messaging v2.1 as a **package within the `vc` project**, complementing the existing OpenID4VCI, OpenID4VP, and W3C VC Data Integrity implementations.

**Target Spec:** https://identity.foundation/didcomm-messaging/spec/v2.1/

### Architectural Decision: Integration into `vc`

DIDComm v2.1 will be implemented as `vc/pkg/didcomm/` rather than a standalone module because:

1. **Protocol Synergy** - DIDComm can transport OID4VCI/OID4VP messages
2. **Shared Infrastructure** - Reuses existing keyresolver, trust, jose, signing packages
3. **Coherent API** - Single import for wallet developers
4. **Consistent Patterns** - Follows vc's established ADRs and build tag conventions

```
┌─────────────────────────────────────────────────────────────┐
│                    vc Project Structure                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
│  │ OpenID4VCI  │   │ OpenID4VP   │   │  DIDComm2   │       │
│  │  (Issuance) │   │(Presentation│   │ (Messaging) │       │
│  │   EXISTING  │   │  EXISTING   │   │    NEW      │       │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘       │
│         │                 │                  │              │
│         └────────┬────────┴────────┬────────┘              │
│                  │                 │                        │
│         ┌────────▼────────┐ ┌──────▼───────┐               │
│         │  keyresolver    │ │    trust     │  EXISTING     │
│         │  (DID/AuthZEN)  │ │  (AuthZEN)   │               │
│         └────────┬────────┘ └──────┬───────┘               │
│                  │                 │                        │
│         ┌────────▼────────┐ ┌──────▼───────┐               │
│         │     jose        │ │   signing    │  EXISTING     │
│         │   (JWK/JWT)     │ │  (Signer)    │               │
│         └─────────────────┘ └──────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

### Package Location

```
vc/pkg/
├── didcomm/                    # NEW: DIDComm v2.1 implementation
│   ├── message/                # Plaintext, signed, encrypted messages
│   ├── crypto/                 # JWE (ECDH-ES, ECDH-1PU), JWS
│   ├── transport/              # HTTP, WebSocket transports
│   ├── routing/                # Forward messages, mediators
│   ├── protocol/               # Trust Ping, OOB, Discover Features
│   │   ├── trustping/
│   │   ├── oob/
│   │   └── discover/
│   └── agent/                  # High-level Agent API
├── keyresolver/                # EXISTING: DID resolution (AuthZEN)
├── trust/                      # EXISTING: Trust evaluation
├── jose/                       # EXISTING: JWK/JWT utilities
├── signing/                    # EXISTING: Signer interface
├── openid4vci/                 # EXISTING: Credential issuance
├── openid4vp/                  # EXISTING: Credential presentation
├── vc20/                       # EXISTING: W3C VC Data Integrity
└── ...
```

### Build Tags

Following vc's existing pattern:
```go
//go:build didcomm

package didcomm
```

Users opt-in to DIDComm support via build tag, keeping the core vc module lightweight.

---

## Design Philosophy

1. **No CGO/Rust runtime dependencies** in the final library
2. **Interoperability confidence** through cross-implementation testing against didcomm-rust
3. **Idiomatic Go** code aligned with vc project ADRs
4. **AuthZEN-native** DID resolution via existing keyresolver

---

## Interoperability Testing Strategy

### Reference Implementation: didcomm-rust via UniFFI

The [sicpa-dlab/didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) library serves as the authoritative reference. We use [eclipse-xfsc/didcomm-v2-connector](https://github.com/eclipse-xfsc/didcomm-v2-connector) Go bindings **exclusively for testing**.

```
┌────────────────────────────────────────────────────────────────────┐
│                    Interoperability Test Harness                    │
├────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────┐         ┌─────────────────────────────┐   │
│  │  vc/pkg/didcomm     │         │  didcomm-rust (via UniFFI)  │   │
│  │   (Native Go)       │◄───────►│  (Reference Implementation) │   │
│  │                     │  Test   │                             │   │
│  │  - Encrypt          │  Cases  │  - Encrypt                  │   │
│  │  - Decrypt          │         │  - Decrypt                  │   │
│  │  - Sign             │         │  - Sign                     │   │
│  │  - Verify           │         │  - Verify                   │   │
│  │  - Pack/Unpack      │         │  - Pack/Unpack              │   │
│  └─────────────────────┘         └─────────────────────────────┘   │
│                                                                      │
│  Test Types:                                                        │
│  • Round-trip: Go encrypts → Rust decrypts (and vice versa)        │
│  • Normalization: Both produce identical JWE/JWS structures        │
│  • Vector validation: Both pass DIDComm spec test vectors          │
│  • Edge cases: Malformed inputs, boundary conditions               │
│                                                                      │
└────────────────────────────────────────────────────────────────────┘
```

### Test Harness Location

```
vc/
├── pkg/didcomm/                # Implementation
└── test/
    └── didcomm_interop/        # Interoperability tests
        ├── harness/            # Rust bridge infrastructure
        │   ├── rust_bridge.go  # UniFFI binding wrapper
        │   ├── resolver.go     # Shared mock resolver
        │   └── keys.go         # Shared test key material
        ├── crypto_test.go      # Encryption/signing interop
        ├── message_test.go     # Message format interop
        ├── routing_test.go     # Forward message interop
        └── vectors/            # DIDComm spec test vectors
```

---

## Phase 0: Interoperability Infrastructure (Week 1)

### 0.1 Rust Bridge Setup
- [ ] Create `test/didcomm_interop/harness/` directory
- [ ] Set up Rust toolchain in CI (for test builds only)
- [ ] Integrate eclipse-xfsc/didcomm-v2-connector as test dependency:
  ```go
  //go:build didcomm_interop
  
  package harness
  
  import didcomm "github.com/eclipse-xfsc/didcomm-v2-connector"
  
  type RustBridge struct {
      dc *didcomm.DidComm
  }
  ```
- [ ] Create shared test key material (Ed25519, X25519, P-256, P-384, secp256k1)
- [ ] Adapt existing keyresolver for Rust DidResolver interface

### 0.2 Test Vector Infrastructure
- [ ] Download/embed DIDComm spec Appendix C test vectors
- [ ] Create test vector loader
- [ ] Validate Rust implementation passes all test vectors (baseline)

### 0.3 CI Configuration
- [ ] Add `test-didcomm-interop` Make target with Rust toolchain
- [ ] Separate CI job for interop tests (heavier dependencies)
- [ ] Nightly interop test runs against latest didcomm-rust

---

## Phase 1: Package Foundation (Week 1-2)

### 1.1 Package Setup
- [ ] Create `pkg/didcomm/` directory structure:
  ```
  pkg/didcomm/
  ├── doc.go                    # Package documentation
  ├── message/                  # Message types
  │   ├── plaintext.go
  │   ├── attachment.go
  │   └── message_test.go
  ├── crypto/                   # Encryption/signing
  │   ├── jwe.go               # JWE operations
  │   ├── jws.go               # JWS operations  
  │   ├── ecdh_es.go           # Anoncrypt
  │   ├── ecdh_1pu.go          # Authcrypt
  │   └── crypto_test.go
  ├── transport/                # Transports
  ├── routing/                  # Routing protocol
  ├── protocol/                 # Built-in protocols
  └── agent/                    # High-level API
  ```
- [ ] Add build tag `//go:build didcomm` to all files
- [ ] Update vc Makefile with DIDComm targets:
  ```makefile
  test-didcomm:
  	go test -tags=didcomm ./pkg/didcomm/...
  
  test-didcomm-interop:
  	go test -tags=didcomm,didcomm_interop ./test/didcomm_interop/...
  ```

### 1.2 Internal Dependencies (No External Additions)

DIDComm uses existing vc dependencies:
```go
import (
    // Existing vc packages - no new go.mod entries needed
    "vc/pkg/keyresolver"     // SmartResolver, GoTrustResolver
    "vc/pkg/trust"           // GoTrustEvaluator
    "vc/pkg/signing"         // Signer interface
    "vc/pkg/jose"            // JWK utilities
    
    // Existing external dependencies (already in vc go.mod)
    "github.com/lestrrat-go/jwx/v3/jwe"
    "github.com/lestrrat-go/jwx/v3/jws"
    "github.com/lestrrat-go/jwx/v3/jwk"
    "golang.org/x/crypto/curve25519"  // X25519
)
```

---

## Phase 2: Message Layer (Week 2-4)

### 2.1 Plaintext Messages (`pkg/didcomm/message`)
- [ ] Define `PlaintextMessage` struct per spec Section 3:
  ```go
  type PlaintextMessage struct {
      ID          string         `json:"id"`
      Type        string         `json:"type"`
      From        string         `json:"from,omitempty"`
      To          []string       `json:"to,omitempty"`
      ThID        string         `json:"thid,omitempty"`
      PThID       string         `json:"pthid,omitempty"`
      CreatedTime int64          `json:"created_time,omitempty"`
      ExpiresTime int64          `json:"expires_time,omitempty"`
      Body        any            `json:"body,omitempty"`
      Attachments []Attachment   `json:"attachments,omitempty"`
      FromPrior   string         `json:"from_prior,omitempty"`
  }
  ```
- [ ] Implement `Attachment` type with base64, links, JWS support
- [ ] Implement message validation
- [ ] JSON serialization/deserialization with media type handling

**🔄 INTEROP CHECKPOINT 2.1**: Message Serialization Parity

### 2.2 Signed Messages (`pkg/didcomm/crypto`)
- [ ] JWS wrapper for plaintext messages
- [ ] Support required algorithms:
  - EdDSA (Ed25519) - **Required**
  - ES256 (P-256) - **Required**
  - ES256K (secp256k1) - **Required**
- [ ] `Sign(message, signer) → SignedMessage` using existing `signing.Signer`
- [ ] `Verify(signedMessage, resolver) → PlaintextMessage` using existing keyresolver

**🔄 INTEROP CHECKPOINT 2.2**: Signature Interoperability

### 2.3 Encrypted Messages (`pkg/didcomm/crypto`)
- [ ] JWE wrapper implementation
- [ ] **Anoncrypt** (ECDH-ES) - anonymous sender
- [ ] **Authcrypt** (ECDH-1PU) - sender authenticated
- [ ] Support required key agreement curves:
  - X25519 - **Required**
  - P-384 - **Required**  
  - P-256 - **Required**
- [ ] Support content encryption:
  - A256CBC-HS512 - **Required for authcrypt**
  - A256GCM - **Recommended for anoncrypt**

**🔄 INTEROP CHECKPOINT 2.3**: Encryption Interoperability (CRITICAL)

### 2.4 JWE Structure Validation
- [ ] Protected header encoding (base64url)
- [ ] Recipient structure for multi-recipient encryption
- [ ] AAD handling

**🔄 INTEROP CHECKPOINT 2.4**: JWE Structure Parity

---

## Phase 3: DID Resolution (Week 4-4.5) - MINIMAL NEW CODE

### 3.1 Adapt Existing keyresolver

The existing `keyresolver` package already handles DID resolution via AuthZEN. We add DIDComm-specific wrappers:

```go
package didcomm

import "vc/pkg/keyresolver"

// Resolver wraps existing keyresolver for DIDComm
type Resolver struct {
    smart *keyresolver.SmartResolver
}

// NewResolver creates a DIDComm resolver using existing infrastructure
func NewResolver(pdpURL string) *Resolver {
    goTrust := keyresolver.NewGoTrustResolver(pdpURL)
    return &Resolver{smart: keyresolver.NewSmartResolver(goTrust)}
}

// ResolveKeyAgreement extracts key agreement keys (X25519, P-256, P-384)
func (r *Resolver) ResolveKeyAgreement(ctx context.Context, did string) ([]KeyAgreementKey, error) {
    // Filter for keyAgreement purpose
}

// ResolveService extracts DIDCommMessaging service endpoints
func (r *Resolver) ResolveService(ctx context.Context, did string) (*DIDCommService, error) {
    // Parse DIDCommMessaging service from DID document
}
```

### 3.2 New DIDComm-Specific Features
- [ ] X25519 key agreement key support
- [ ] DIDCommMessaging service endpoint parsing
- [ ] Service endpoint routing key extraction

### 3.3 Key Store for Decryption

Extend existing signing.Signer pattern:
```go
type KeyAgreementStore interface {
    GetKeyAgreementKey(ctx context.Context, kid string) (any, error)
    ListKeyAgreementKeys(ctx context.Context) ([]string, error)
}
```

**🔄 INTEROP CHECKPOINT 3**: Resolver Compatibility

---

## Phase 4: Transport Layer (Week 4.5-6.5)

### 4.1 Transport Interface (`pkg/didcomm/transport`)
```go
type Transport interface {
    Send(ctx context.Context, endpoint string, message []byte, contentType string) (*Response, error)
    Listen(handler MessageHandler) error
    Close() error
}
```

### 4.2 HTTPS Transport
- [ ] HTTP POST sender per spec Section 8.5.1
- [ ] Content-Type header handling
- [ ] TLS 1.2+ with PFS
- [ ] HTTP server for receiving messages

### 4.3 WebSocket Transport
- [ ] WebSocket client/server per spec Section 8.5.2
- [ ] Secure WebSocket (wss://)
- [ ] Per-message encryption

**🔄 INTEROP CHECKPOINT 4**: End-to-End Message Exchange

---

## Phase 5: Routing Protocol (Week 6.5-8.5)

### 5.1 Forward Messages (`pkg/didcomm/routing`)
- [ ] Implement `forward` message type
- [ ] Message wrapping for routing keys
- [ ] Unwrapping at mediator

### 5.2 Service Endpoint Resolution
- [ ] Parse `DIDCommMessaging` service endpoints
- [ ] Handle DID-as-endpoint (mediator DIDs)

### 5.3 Route Building
- [ ] Multi-hop wrapping per spec Section 9.4.6

**🔄 INTEROP CHECKPOINT 5**: Routing Interoperability

---

## Phase 6: Core Protocols (Week 8.5-10)

### 6.1 Trust Ping 2.0 (`pkg/didcomm/protocol/trustping`)
- [ ] `ping` and `ping-response` messages

### 6.2 Discover Features 2.0 (`pkg/didcomm/protocol/discover`)
- [ ] `query` and `disclose` messages

### 6.3 Out-of-Band 2.0 (`pkg/didcomm/protocol/oob`)
- [ ] `invitation` message type
- [ ] URL encoding (`_oob` query parameter)

### 6.4 Problem Reports (`pkg/didcomm/protocol/problem`)
- [ ] Problem report message structure

**🔄 INTEROP CHECKPOINT 6**: Protocol Message Interoperability

---

## Phase 7: High-Level API (Week 10-11)

### 7.1 Agent Interface (`pkg/didcomm/agent`)
```go
type Agent struct {
    DID             string
    KeyStore        KeyAgreementStore
    Signer          signing.Signer
    Resolver        *Resolver
    Transport       Transport
}

func (a *Agent) SendMessage(ctx context.Context, to string, msg *PlaintextMessage) error
func (a *Agent) ReceiveMessage(ctx context.Context, encrypted []byte) (*PlaintextMessage, *MessageMetadata, error)
func (a *Agent) RegisterProtocol(protocol Protocol) error
```

### 7.2 Protocol Handler Framework
```go
type Protocol interface {
    Name() string
    Version() string
    SupportedTypes() []string
    HandleMessage(ctx context.Context, msg *PlaintextMessage, meta *MessageMetadata) (*PlaintextMessage, error)
}
```

**🔄 INTEROP CHECKPOINT 7**: Full Agent Interoperability

---

## Phase 8: Testing & Documentation (Week 11-12)

### 8.1 Test Suite
- [ ] Unit tests (>70% coverage, >80% for crypto)
- [ ] Integration tests with spec test vectors
- [ ] Interoperability tests against Rust reference
- [ ] Fuzz testing for message parsing

### 8.2 Documentation
- [ ] GoDoc comments on all exported types/functions
- [ ] Usage examples in `/examples/didcomm/`
- [ ] Integration guide: DIDComm + OID4VCI/VP

---

## Milestone Summary

| Milestone | Deliverable | Target | Interop Gate |
|-----------|-------------|--------|--------------|
| M0 | Rust bridge + test vectors | Week 1 | Rust passes all vectors |
| M1 | Package structure, build tags | Week 2 | - |
| M2 | Plaintext, Signed, Encrypted messages | Week 4 | **Checkpoints 2.1-2.4 pass** |
| M3 | DID resolution adapters | Week 4.5 | Checkpoint 3 passes |
| M4 | HTTPS + WebSocket transports | Week 6.5 | Checkpoint 4 passes |
| M5 | Routing protocol | Week 8.5 | **Checkpoint 5 passes** |
| M6 | Core protocols | Week 10 | Checkpoint 6 passes |
| M7 | High-level Agent API | Week 11 | **Checkpoint 7 passes** |
| M8 | Test coverage >70%, docs | Week 12 | All checkpoints green |

---

## Component Reuse Summary

### Existing vc Components (No New Code)

| Component | vc Package | Status |
|-----------|------------|--------|
| AuthZEN DID Resolution | `pkg/keyresolver/gotrust_adapter.go` | ✅ Ready |
| Smart Resolver | `pkg/keyresolver/resolver.go` | ✅ Ready |
| did:key, did:jwk parsing | `pkg/keyresolver/resolver.go` | ✅ Ready |
| Trust evaluation | `pkg/trust/gotrust.go` | ✅ Ready |
| Signer interface | `pkg/signing/signer.go` | ✅ Ready |
| JWK utilities | `pkg/jose/jwk.go` | ✅ Ready |
| JOSE library | `github.com/lestrrat-go/jwx/v3` | ✅ In go.mod |

### New Code Required for DIDComm

| Component | Location | Reason |
|-----------|----------|--------|
| X25519 key agreement | `pkg/didcomm/crypto/` | vc focuses on signing |
| ECDH-ES / ECDH-1PU | `pkg/didcomm/crypto/` | JWE encryption |
| JWE encryption/decryption | `pkg/didcomm/crypto/` | DIDComm authcrypt/anoncrypt |
| DIDCommMessaging service | `pkg/didcomm/` | DIDComm-specific endpoint format |
| Forward message wrapping | `pkg/didcomm/routing/` | Routing protocol |
| HTTP/WebSocket transport | `pkg/didcomm/transport/` | DIDComm-specific |
| Protocol implementations | `pkg/didcomm/protocol/` | Trust Ping, OOB, etc. |

---

## Interoperability Test Matrix

### Cryptographic Operations (CRITICAL)

| Operation | Algorithm | Go→Rust | Rust→Go | Status |
|-----------|-----------|---------|---------|--------|
| Sign | EdDSA | ⬜ | ⬜ | - |
| Sign | ES256 | ⬜ | ⬜ | - |
| Sign | ES256K | ⬜ | ⬜ | - |
| Encrypt (anoncrypt) | X25519+A256GCM | ⬜ | ⬜ | - |
| Encrypt (anoncrypt) | P-256+A256GCM | ⬜ | ⬜ | - |
| Encrypt (anoncrypt) | P-384+A256GCM | ⬜ | ⬜ | - |
| Encrypt (authcrypt) | X25519+A256CBC-HS512 | ⬜ | ⬜ | - |
| Encrypt (authcrypt) | P-256+A256CBC-HS512 | ⬜ | ⬜ | - |
| Encrypt (authcrypt) | P-384+A256CBC-HS512 | ⬜ | ⬜ | - |

### Message Processing

| Scenario | Go→Rust | Rust→Go | Status |
|----------|---------|---------|--------|
| Plaintext round-trip | ⬜ | ⬜ | - |
| Multi-recipient encryption | ⬜ | ⬜ | - |
| Signed-then-encrypted | ⬜ | ⬜ | - |
| Forward message (1 hop) | ⬜ | ⬜ | - |
| Forward message (3 hops) | ⬜ | ⬜ | - |
| Trust Ping conversation | ⬜ | ⬜ | - |
| OOB invitation parse | ⬜ | ⬜ | - |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| JOSE library compatibility | Use same library as vc (lestrrat-go/jwx/v3) |
| X25519/ECDH-1PU complexity | Validate every step against Rust reference |
| API conflicts with existing vc | Use build tags, separate package namespace |
| Interoperability issues | Catch early via continuous interop testing |
| Rust toolchain in CI | Use pre-built UniFFI bindings; cache Cargo builds |

---

## Integration Examples

### Using DIDComm with OpenID4VCI

```go
//go:build didcomm

package main

import (
    "vc/pkg/didcomm"
    "vc/pkg/didcomm/agent"
    "vc/pkg/didcomm/protocol/oob"
    "vc/pkg/openid4vci"
)

func main() {
    // Create DIDComm agent
    dcAgent := agent.New(agent.Config{
        DID:      "did:web:wallet.example.com",
        Resolver: didcomm.NewResolver("https://pdp.example.com"),
    })
    
    // Receive OOB invitation containing OID4VCI offer
    invitation, _ := oob.ParseURL(invitationURL)
    
    // The invitation body may contain an OID4VCI credential offer
    if offer, ok := invitation.Body.Attachments[0].Data.(openid4vci.CredentialOffer); ok {
        // Process credential offer via OID4VCI
        client := openid4vci.NewClient(offer.CredentialIssuer)
        // ...
    }
}
```

---

## References

- [DIDComm v2.1 Spec](https://identity.foundation/didcomm-messaging/spec/v2.1/)
- [DIDComm Test Vectors](https://identity.foundation/didcomm-messaging/spec/v2.1/#appendix-c-test-vectors)
- [sicpa-dlab/didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) - Reference implementation
- [eclipse-xfsc/didcomm-v2-connector](https://github.com/eclipse-xfsc/didcomm-v2-connector) - UniFFI Go bindings
- [ECDH-1PU Draft](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
