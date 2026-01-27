// Package pki provides interfaces and implementations for cryptographic signing operations.
// It supports multiple backends including software keys and PKCS#11 hardware security modules.
package pki

import "context"

// Signer defines the interface for cryptographic signing operations.
// Implementations can use software keys, HSMs via PKCS#11, cloud KMS, etc.
type Signer interface {
	// Sign signs the provided data and returns the signature.
	Sign(ctx context.Context, data []byte) ([]byte, error)

	// Algorithm returns the JWT algorithm name (e.g., "RS256", "ES256").
	Algorithm() string

	// KeyID returns the key identifier for the JWT kid header.
	KeyID() string

	// PublicKey returns the public key for verification purposes.
	PublicKey() any
}
