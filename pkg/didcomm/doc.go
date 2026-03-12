// Package didcomm implements DIDComm Messaging v2.1 specification.
//
// DIDComm Messaging is a secure, private communication methodology built atop
// the decentralized design of DIDs. It provides:
//   - End-to-end encryption between parties identified by DIDs
//   - Authentication of message senders
//   - Routing through mediators for asynchronous delivery
//   - Protocol negotiation and extensibility
//
// This package is integrated with the vc project's existing infrastructure:
//   - keyresolver: For DID document and key resolution via AuthZEN
//   - trust: For trust evaluation of communication partners
//   - jose: For JWK/JWT operations
//   - signing: For cryptographic signing operations
//
// # Architecture
//
// The package is organized into sub-packages:
//
//   - message: Core message types (plaintext, signed, encrypted)
//   - crypto: JWE encryption (ECDH-ES, ECDH-1PU) and JWS signing
//   - transport: HTTP and WebSocket transport implementations
//   - routing: Forward messages and mediator support
//   - protocol: Built-in protocols (Trust Ping, OOB, Discover Features)
//   - agent: High-level Agent API for building DIDComm applications
//
// # Build Tags
//
// This package requires the "didcomm" build tag:
//
//	go build -tags=didcomm ./...
//	go test -tags=didcomm ./pkg/didcomm/...
//
// # Quick Start
//
//	import (
//	    "vc/pkg/didcomm"
//	    "vc/pkg/didcomm/message"
//	    "vc/pkg/didcomm/agent"
//	)
//
//	// Create a DIDComm agent
//	a := agent.New(agent.Config{
//	    DID:      "did:web:example.com",
//	    Resolver: didcomm.NewResolver("https://pdp.example.com"),
//	})
//
//	// Send a message
//	msg := message.New(
//	    message.WithType("https://example.com/protocols/1.0/ping"),
//	    message.WithTo([]string{"did:web:recipient.com"}),
//	)
//	err := a.Send(ctx, msg)
//
// # Specification
//
// This implementation follows DIDComm Messaging v2.1:
// https://identity.foundation/didcomm-messaging/spec/v2.1/
//
// # Interoperability
//
// The implementation is tested against the didcomm-rust reference implementation
// via eclipse-xfsc/didcomm-v2-connector UniFFI bindings.
package didcomm
