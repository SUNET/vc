# ADR-016: DIDComm v2.1 Integration

## Status

Accepted

## Context

The `vc` project provides a comprehensive Go implementation of verifiable credentials protocols:
- OpenID4VCI (credential issuance)
- OpenID4VP (credential presentation)  
- W3C VC Data Integrity (proof generation/verification)

A separate `go-didcomm2` project was started to implement DIDComm Messaging v2.1. Analysis revealed significant overlap with existing `vc` infrastructure:

- **keyresolver** - AuthZEN-based DID resolution with smart routing
- **trust** - Trust evaluation via AuthZEN PDP
- **signing** - Generic Signer interface
- **jose** - JWK/JWT utilities using lestrrat-go/jwx/v3
- **vc20/crypto** - EdDSA and ECDSA signing suites

## Decision

Integrate DIDComm v2.1 implementation into the `vc` project as `pkg/didcomm/` rather than maintaining a separate repository.

### Package Structure

```
pkg/didcomm/
├── message/      # Plaintext, signed, encrypted messages
├── crypto/       # JWE (ECDH-ES, ECDH-1PU), JWS operations
├── transport/    # HTTP, WebSocket transports
├── routing/      # Forward messages, mediators
├── protocol/     # Trust Ping, OOB, Discover Features
└── agent/        # High-level Agent API
```

### Build Tags

All DIDComm files use `//go:build didcomm` to make the feature opt-in.

## Rationale

### Protocol Synergy
DIDComm can transport OID4VCI/OID4VP messages. Out-of-Band (OOB) invitations may contain credential offers. Integration enables seamless interoperability.

### Shared Infrastructure
- **~21% effort reduction** by reusing existing packages
- No new external dependencies needed (lestrrat-go/jwx/v3 already in go.mod)
- Consistent AuthZEN trust model across all protocols

### Developer Experience
Single import path for wallet developers working with VCs and secure messaging:
```go
import (
    "vc/pkg/openid4vci"
    "vc/pkg/openid4vp"  
    "vc/pkg/didcomm"
)
```

### ADR Consistency
DIDComm follows established project ADRs:
- ADR-01: No custom cryptography
- ADR-02: >70% test coverage
- ADR-03: Use `any` type
- ADR-05: AuthZEN client integration

## Alternatives Considered

### Separate Repository (go-didcomm2)
- **Pro**: Independent versioning, separate maintainers
- **Con**: Duplicate infrastructure, import complexity, potential divergence

### Import vc as Dependency
- **Pro**: Keep projects separate
- **Con**: Circular dependency risk, version coordination overhead

## Consequences

### Positive
- Unified codebase for SSI/VC/DIDComm protocols
- Simplified maintenance and testing
- Coherent API for consumers
- Shared CI/CD pipeline

### Negative
- Larger vc repository
- Build tags required for optional DIDComm feature
- Migration effort for anyone already using go-didcomm2 ADRs

## Implementation

See [DIDCOMM_IMPLEMENTATION_PLAN.md](../DIDCOMM_IMPLEMENTATION_PLAN.md) for detailed phases and timeline.

## References

- [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/)
- [go-didcomm2 ADRs](../../go-didcomm2/docs/adr/) - Original project ADRs
- [sicpa-dlab/didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) - Reference implementation
