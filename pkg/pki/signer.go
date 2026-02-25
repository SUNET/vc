// Package pki provides interfaces and implementations for cryptographic signing operations.
// It supports multiple backends including software keys and PKCS#11 hardware security modules.
package pki

import "context"

// Signer defines the interface for cryptographic signing operations.
// Implementations can use software keys, HSMs via PKCS#11, cloud KMS, etc.
type Signer interface {
	// Sign signs the provided data and returns the signature.
	//
	// For ECDSA algorithms (ES256, ES384, ES512), the returned signature SHOULD be
	// in IEEE P1363 format (fixed-size R||S concatenation) as required by JWS (RFC 7518 §3.4).
	// If the implementation returns ASN.1 DER-encoded ECDSA signatures instead (as is
	// common with crypto.Signer and some HSM backends), the jose.MakeJWT function will
	// automatically convert them to JWS format. However, returning IEEE P1363 directly
	// avoids the conversion overhead.
	//
	// For RSA algorithms (RS256, RS384, RS512), the signature is PKCS#1 v1.5 encoded
	// and requires no format conversion.
	Sign(ctx context.Context, data []byte) ([]byte, error)

	// Algorithm returns the JWT algorithm name (e.g., "RS256", "ES256").
	Algorithm() string

	// KeyID returns the key identifier for the JWT kid header.
	KeyID() string

	// PublicKey returns the public key for verification purposes.
	PublicKey() any
}

// RawSigner extends Signer with direct signature operations for advanced use cases
// like W3C Data Integrity proofs where the caller controls hashing.
//
// This interface is particularly useful for:
// - VC 2.0 Data Integrity cryptosuites (ecdsa-rdfc-2019, eddsa-rdfc-2022, etc.)
// - Any protocol that requires signing pre-computed digests
// - Fine-grained control over the hash-then-sign process
type RawSigner interface {
	Signer

	// SignDigest signs a pre-computed digest without additional hashing.
	//
	// For ECDSA, the digest should be the appropriate size for the curve:
	// - P-256: SHA-256 (32 bytes)
	// - P-384: SHA-384 (48 bytes)
	// - P-521: SHA-512 (64 bytes)
	//
	// For EdDSA (Ed25519), note that Ed25519 does not use pre-hashing in standard mode.
	// The implementation may need to use Ed25519ph (pre-hashed) or handle this specially.
	//
	// The returned signature is in IEEE P1363 format for ECDSA (R||S concatenation).
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}
