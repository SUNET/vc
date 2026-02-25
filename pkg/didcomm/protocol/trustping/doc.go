//go:build didcomm && vc20

// Package trustping implements the DIDComm Trust Ping Protocol 2.0.
//
// Trust Ping is used to test connectivity and verify that an agent is
// online and responsive.
//
// Protocol URI: https://didcomm.org/trust-ping/2.0
//
// # Message Types
//
//   - ping: Request a response from the receiver
//   - ping-response: Response to a ping request
//
// # Usage
//
//	// Create and send a ping
//	ping := trustping.NewPing(
//		"did:example:alice",
//		"did:example:bob",
//		trustping.WithResponseRequested(true),
//		trustping.WithComment("Hello!"),
//	)
//
//	// Handle a received ping
//	response, err := trustping.HandlePing(msg)
package trustping
