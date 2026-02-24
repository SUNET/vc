//go:build didcomm && vc20

// Package oob implements the DIDComm Out-of-Band Protocol 2.0.
//
// Out-of-Band is used to share out-of-band invitations that can
// bootstrap DIDComm connections through other channels like QR codes,
// URLs, or email.
//
// Protocol URI: https://didcomm.org/out-of-band/2.0
//
// # Message Types
//
//   - invitation: An invitation to connect or interact
//
// # Usage
//
//	// Create an invitation
//	inv := oob.NewInvitation(
//		"did:example:alice",
//		oob.WithGoal("To establish a secure connection"),
//		oob.WithAccept(didcomm.MediaTypeEncrypted),
//	)
//
//	// Encode for transport
//	url, _ := oob.EncodeAsURL(inv, "https://example.com")
//	qr, _ := oob.EncodeAsJSON(inv)
//
//	// Decode a received invitation
//	inv, _ := oob.DecodeFromURL(url)
package oob
