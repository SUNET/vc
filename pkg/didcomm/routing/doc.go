// Package routing implements DIDComm v2.1 message routing.
//
// The routing package provides support for DIDComm mediators and message
// forwarding as defined in the DIDComm Messaging v2.1 specification
// (Section 9: Routing Protocol 2.0).
//
// # Forward Messages
//
// When a sender cannot deliver directly to a recipient, they can wrap the
// message in a forward envelope addressed to a mediator:
//
//	forward := routing.NewForward(
//	    "did:example:mediator",     // mediator DID
//	    "did:example:recipient",    // final recipient
//	    encryptedMessage,           // the wrapped message
//	)
//
// # Route Building
//
// The RouteBuilder constructs multi-hop routes by analyzing service endpoints:
//
//	builder := routing.NewRouteBuilder(resolver)
//	route, err := builder.BuildRoute(ctx, recipientDID)
//	// route contains the sequence of hops needed
//
// # Message Wrapping
//
// For multi-hop routing, messages are wrapped in nested forward envelopes:
//
//	wrapped, err := routing.WrapForRoute(ctx, message, route, encrypter)
//	// wrapped is ready to send to the first hop
//
// # Mediator Support
//
// The package supports both sender-side wrapping and mediator-side unwrapping:
//
//	// At mediator: unwrap and forward
//	inner, nextHop, err := routing.UnwrapForward(ctx, received, decrypter)
//
// See the DIDComm v2.1 specification for complete routing protocol details:
// https://identity.foundation/didcomm-messaging/spec/v2.1/#routing-protocol-20
package routing
