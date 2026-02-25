//go:build didcomm && vc20

// Package protocol implements DIDComm v2.1 protocols.
//
// This package provides implementations of standard DIDComm protocols:
//
//   - Trust Ping: Test connectivity and responsiveness
//   - Out-of-Band: Exchange out-of-band invitations
//   - Discover Features: Query supported protocols and features
//
// # Usage
//
// Protocols can be used directly or through the Agent:
//
//	// Create a trust ping request
//	pingMsg := trustping.NewPing(
//		"did:example:alice",
//		"did:example:bob",
//		trustping.WithResponseRequested(true),
//	)
//
//	// Process a received ping
//	response, err := trustping.HandlePing(receivedMsg)
//
// # Supported Protocols
//
//	https://didcomm.org/trust-ping/2.0        - Connectivity testing
//	https://didcomm.org/out-of-band/2.0       - Out-of-band invitations
//	https://didcomm.org/discover-features/2.0 - Feature discovery
package protocol
