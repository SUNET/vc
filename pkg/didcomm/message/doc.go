//go:build didcomm && vc20

// Package message provides DIDComm v2.1 message types and operations.
//
// This package implements the core message structures defined in the
// DIDComm Messaging v2.1 specification:
//   - Plaintext messages (Section 3)
//   - Attachments (Section 3.4)
//   - Message validation
//
// # Message Types
//
// DIDComm messages are JSON objects with specific required and optional fields.
// The base Message type represents a plaintext message that can be:
//   - Sent as-is (unprotected, for testing only)
//   - Signed to create a SignedMessage (JWS)
//   - Encrypted to create an EncryptedMessage (JWE)
//
// # Creating Messages
//
//	msg := message.New(
//	    message.WithType("https://example.com/protocols/1.0/hello"),
//	    message.WithTo("did:example:bob"),
//	    message.WithFrom("did:example:alice"),
//	    message.WithBody(map[string]any{"greeting": "Hello, Bob!"}),
//	)
//
// # Attachments
//
// Messages can include attachments with various data formats:
//
//	msg.AddAttachment(message.Attachment{
//	    ID:          "doc-1",
//	    MediaType:   "application/pdf",
//	    Data:        message.AttachmentData{Base64: encodedPDF},
//	})
package message
