// Package crypto provides cryptographic interfaces and utilities for VC 2.0 Data Integrity proofs.
package crypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/SUNET/vc/pkg/pki"
)

// VCSigner abstracts signing operations for Verifiable Credentials Data Integrity proofs.
// It supports both raw crypto keys and pki.RawSigner implementations (including HSMs).
//
// The key difference from pki.Signer is that VCSigner operates on pre-computed digests,
// which is required by Data Integrity cryptosuites where the caller controls the hashing.
type VCSigner interface {
	// SignDigest signs a pre-hashed value without additional hashing.
	// For ECDSA, returns IEEE P1363 format (R||S concatenation).
	// For EdDSA, the digest is the full message to sign (Ed25519 doesn't pre-hash).
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)

	// PublicKey returns the verification key.
	PublicKey() crypto.PublicKey

	// Algorithm returns the cryptographic algorithm identifier (e.g., "ES256", "Ed25519").
	Algorithm() string
}

// ECDSAKeyWrapper wraps an *ecdsa.PrivateKey to implement VCSigner.
// This provides backward compatibility with existing code that uses raw ECDSA keys.
type ECDSAKeyWrapper struct {
	key       *ecdsa.PrivateKey
	algorithm string
}

// NewECDSAKeyWrapper creates a new VCSigner from an ECDSA private key.
func NewECDSAKeyWrapper(key *ecdsa.PrivateKey) *ECDSAKeyWrapper {
	algorithm := ecdsaAlgorithmForCurve(key.Curve)
	return &ECDSAKeyWrapper{
		key:       key,
		algorithm: algorithm,
	}
}

// SignDigest signs a pre-computed digest using ECDSA.
// Returns the signature in IEEE P1363 format (R||S concatenation).
//
// NOTE: The digest length should match the curve's hash size requirement:
//   - P-256 (ES256): 32 bytes (SHA-256)
//   - P-384 (ES384): 48 bytes (SHA-384)
//   - P-521 (ES512): 64 bytes (SHA-512)
//
// If the digest is longer than the curve's bit size, ecdsa.Sign will only use the
// leftmost bits up to the curve order size. Callers should ensure proper hashing.
func (w *ECDSAKeyWrapper) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, w.key, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}
	sig, err := pki.EncodeECDSASignature(r, s, w.key.Curve)
	if err != nil {
		return nil, fmt.Errorf("signature encoding failed: %w", err)
	}
	return sig, nil
}

// PublicKey returns the ECDSA public key.
func (w *ECDSAKeyWrapper) PublicKey() crypto.PublicKey {
	return &w.key.PublicKey
}

// Algorithm returns the algorithm identifier (ES256, ES384, ES512).
func (w *ECDSAKeyWrapper) Algorithm() string {
	return w.algorithm
}

// EdDSAKeyWrapper wraps an ed25519.PrivateKey to implement VCSigner.
// This provides backward compatibility with existing code that uses raw Ed25519 keys.
type EdDSAKeyWrapper struct {
	key ed25519.PrivateKey
}

// NewEdDSAKeyWrapper creates a new VCSigner from an Ed25519 private key.
func NewEdDSAKeyWrapper(key ed25519.PrivateKey) *EdDSAKeyWrapper {
	return &EdDSAKeyWrapper{key: key}
}

// SignDigest signs a message using Ed25519.
// Note: Ed25519 doesn't use pre-hashing in standard mode, so "digest" is actually
// the full message to be signed (the hash concatenation from Data Integrity proofs).
func (w *EdDSAKeyWrapper) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	signature := ed25519.Sign(w.key, digest)
	return signature, nil
}

// PublicKey returns the Ed25519 public key.
func (w *EdDSAKeyWrapper) PublicKey() crypto.PublicKey {
	return w.key.Public()
}

// Algorithm returns "Ed25519".
func (w *EdDSAKeyWrapper) Algorithm() string {
	return "Ed25519"
}

// PKISignerWrapper wraps a pki.RawSigner to implement VCSigner.
// This enables HSM-based signing via the pki package.
type PKISignerWrapper struct {
	signer pki.RawSigner
}

// NewPKISignerWrapper creates a new VCSigner from a pki.RawSigner.
// Use this to integrate with the pki package for HSM or managed key support.
func NewPKISignerWrapper(signer pki.RawSigner) *PKISignerWrapper {
	return &PKISignerWrapper{signer: signer}
}

// SignDigest delegates to the underlying pki.RawSigner.
func (w *PKISignerWrapper) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	return w.signer.SignDigest(ctx, digest)
}

// PublicKey returns the public key from the underlying signer.
func (w *PKISignerWrapper) PublicKey() crypto.PublicKey {
	pub := w.signer.PublicKey()
	if cpub, ok := pub.(crypto.PublicKey); ok {
		return cpub
	}
	return nil
}

// Algorithm returns the algorithm from the underlying signer.
func (w *PKISignerWrapper) Algorithm() string {
	return w.signer.Algorithm()
}

// Helper functions

// ecdsaAlgorithmForCurve returns the JWT algorithm name for an elliptic curve.
func ecdsaAlgorithmForCurve(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	default:
		return "ES256" // Default fallback
	}
}

// DecodeIEEEP1363 decodes an IEEE P1363 format ECDSA signature to (r, s) big integers.
// Useful for verification routines.
func DecodeIEEEP1363(signature []byte, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	return pki.DecodeECDSASignature(signature, curve)
}
