//go:build didcomm && vc20

// Package agent provides a high-level DIDComm agent implementation.
//
// The Agent is the main entry point for DIDComm messaging. It coordinates:
//   - Message creation and sending
//   - Message receiving and processing
//   - Protocol dispatching
//   - Key management integration
//
// # Basic Usage
//
//	// Create an agent
//	agent, err := agent.New(
//		agent.WithDID("did:example:alice"),
//		agent.WithResolver(resolver),
//		agent.WithKeyStore(keyStore),
//	)
//
//	// Send a message
//	response, err := agent.Send(ctx, "did:example:bob", message)
//
//	// Register protocol handlers
//	agent.RegisterHandler("https://didcomm.org/trust-ping/2.0/ping", pingHandler)
//
// # Processing Incoming Messages
//
//	// Use the agent as an HTTP handler
//	http.Handle("/didcomm", agent.HTTPHandler())
//
// # Protocol Support
//
// The agent includes built-in support for:
//   - Trust Ping (connectivity testing)
//   - Discover Features (capability discovery)
//   - Out-of-Band (connection bootstrapping)
package agent
