// Package crypto provides cryptographic operations for DIDComm v2.1.
//
// This package implements:
//   - JWE encryption (anoncrypt with ECDH-ES, authcrypt with ECDH-1PU)
//   - JWS signing for signed messages
//   - Key derivation for ECDH key agreement
//
// # Encryption Modes
//
// DIDComm supports two encryption modes:
//
// Anoncrypt (Anonymous Encryption): Uses ECDH-ES for key agreement.
// The sender is anonymous and cannot be authenticated from the ciphertext.
//
//	encrypted, err := crypto.Anoncrypt(message, recipientKeys)
//
// Authcrypt (Authenticated Encryption): Uses ECDH-1PU for key agreement.
// The sender is authenticated and the recipient can verify who sent the message.
//
//	encrypted, err := crypto.Authcrypt(message, senderKey, recipientKeys)
//
// # Content Encryption
//
// Supported content encryption algorithms:
//   - A256GCM (recommended for anoncrypt)
//   - A256CBC-HS512 (required for authcrypt)
//
// # Key Agreement Curves
//
// Supported curves for key agreement:
//   - X25519 (required)
//   - P-256 (required)
//   - P-384 (required)
//
// # Signing
//
// Supported signing algorithms:
//   - EdDSA with Ed25519 (required)
//   - ES256 with P-256 (required)
//   - ES256K with secp256k1 (required)
package crypto
