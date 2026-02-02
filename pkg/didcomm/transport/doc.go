//go:build didcomm && vc20

// Package transport implements DIDComm v2.1 message transports.
//
// This package provides implementations for sending and receiving
// DIDComm messages over various protocols:
//
//   - HTTP: RESTful endpoint for DIDComm messages
//   - WebSocket: Bidirectional persistent connections
//
// # HTTP Transport
//
// The HTTP transport implements DIDComm over HTTP per the specification.
// Messages are sent as POST requests with appropriate content types.
//
//	client := transport.NewHTTPClient()
//	response, err := client.Send(ctx, "https://example.com/didcomm", message)
//
// # Server Handler
//
// For receiving messages, use the HTTP handler:
//
//	handler := transport.NewHTTPHandler(processor)
//	http.Handle("/didcomm", handler)
//
// # Media Types
//
// The transport layer handles content-type negotiation:
//
//	application/didcomm-plain+json    - Plaintext messages
//	application/didcomm-signed+json   - Signed messages
//	application/didcomm-encrypted+json - Encrypted messages
package transport
