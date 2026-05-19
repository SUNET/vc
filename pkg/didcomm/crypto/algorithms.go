// Package crypto provides cryptographic primitives for DIDComm v2.1 messaging.
//
// This package implements the cryptographic algorithms required by the DIDComm
// Messaging specification (https://identity.foundation/didcomm-messaging/spec/v2.1/).
//
// # Supported Algorithms
//
// Key Agreement (for encryption):
//   - ECDH-ES+A256KW: Ephemeral-Static ECDH with AES-256 Key Wrap (anoncrypt)
//   - ECDH-1PU+A256KW: ECDH-1PU with AES-256 Key Wrap (authcrypt)
//
// Content Encryption:
//   - A256GCM: AES-256-GCM
//   - A256CBC-HS512: AES-256-CBC with HMAC-SHA-512
//   - XC20P: XChaCha20-Poly1305 (DIDComm anoncrypt default)
//
// Signing:
//   - EdDSA: Ed25519
//   - ES256: ECDSA with P-256 and SHA-256
//   - ES256K: ECDSA with secp256k1 and SHA-256
//
// # Interoperability
//
// The implementation targets interoperability with the sicpa-dlab/didcomm-rust
// reference implementation. See the test/didcomm_interop directory for
// interoperability tests.
package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Key Agreement Algorithms
const (
	AlgECDHESA256KW  = "ECDH-ES+A256KW"  // ECDH-ES with AES-256 Key Wrap (anoncrypt)
	AlgECDHESA128KW  = "ECDH-ES+A128KW"  // ECDH-ES with AES-128 Key Wrap
	AlgECDH1PUA256KW = "ECDH-1PU+A256KW" // ECDH-1PU with AES-256 Key Wrap (authcrypt)
)

// Content Encryption Algorithms
const (
	EncA256GCM      = "A256GCM"       // AES-256-GCM content encryption
	EncA256CBCHS512 = "A256CBC-HS512" // AES-256-CBC with HMAC-SHA-512
	EncXC20P        = "XC20P"         // XChaCha20-Poly1305 content encryption (DIDComm default for anoncrypt)
	EncA128GCM      = "A128GCM"       // AES-128-GCM content encryption
	EncA128CBCHS256 = "A128CBC-HS256" // AES-128-CBC with HMAC-SHA-256
)

// Signing Algorithms
const (
	SigEdDSA  = "EdDSA"  // EdDSA signing (Ed25519)
	SigES256  = "ES256"  // ECDSA with P-256 and SHA-256
	SigES256K = "ES256K" // ECDSA with secp256k1 and SHA-256
	SigES384  = "ES384"  // ECDSA with P-384 and SHA-384
	SigES512  = "ES512"  // ECDSA with P-521 and SHA-512
)

// Curve names
const (
	CurveX25519    = "X25519"    // Curve25519 for key agreement
	CurveEd25519   = "Ed25519"   // Ed25519 for signing
	CurveP256      = "P-256"     // NIST P-256
	CurveP384      = "P-384"     // NIST P-384
	CurveP521      = "P-521"     // NIST P-521
	CurveSecp256k1 = "secp256k1" // secp256k1 (Bitcoin/Ethereum curve)
)

// AlgorithmSupport indicates the support level for an algorithm.
type AlgorithmSupport int

const (
	SupportNative         AlgorithmSupport = iota // Algorithm is natively supported by jwx
	SupportCustom                                 // We have a custom implementation
	SupportNotImplemented                         // Algorithm is recognized but not yet implemented
	SupportUnknown                                // Algorithm is not recognized
)

// KeyAlgorithmInfo contains information about a key agreement algorithm.
type KeyAlgorithmInfo struct {
	Name              string
	Support           AlgorithmSupport
	RequiresSenderKey bool // Indicates if the algorithm requires a sender key (authcrypt)
}

// ContentAlgorithmInfo contains information about a content encryption algorithm.
type ContentAlgorithmInfo struct {
	Name      string
	Support   AlgorithmSupport
	KeySize   int // Required key size in bytes
	NonceSize int // Required nonce size in bytes
	TagSize   int // Authentication tag size in bytes
}

// keyAlgorithms maps algorithm names to their info.
var keyAlgorithms = map[string]KeyAlgorithmInfo{
	AlgECDHESA256KW: {
		Name:              AlgECDHESA256KW,
		Support:           SupportNative,
		RequiresSenderKey: false,
	},
	AlgECDHESA128KW: {
		Name:              AlgECDHESA128KW,
		Support:           SupportNative,
		RequiresSenderKey: false,
	},
	AlgECDH1PUA256KW: {
		Name:              AlgECDH1PUA256KW,
		Support:           SupportCustom, // Requires custom implementation
		RequiresSenderKey: true,
	},
	// Aliases for convenience
	"ECDH-ES": {
		Name:              AlgECDHESA256KW, // Normalize to full name
		Support:           SupportNative,
		RequiresSenderKey: false,
	},
	"ECDH-1PU": {
		Name:              AlgECDH1PUA256KW, // Normalize to full name
		Support:           SupportCustom,
		RequiresSenderKey: true,
	},
}

// contentAlgorithms maps algorithm names to their info.
var contentAlgorithms = map[string]ContentAlgorithmInfo{
	EncA256GCM: {
		Name:      EncA256GCM,
		Support:   SupportNative,
		KeySize:   32,
		NonceSize: 12,
		TagSize:   16,
	},
	EncA256CBCHS512: {
		Name:      EncA256CBCHS512,
		Support:   SupportNative,
		KeySize:   64, // 32 for AES + 32 for HMAC
		NonceSize: 16,
		TagSize:   32, // Truncated to 32 bytes
	},
	EncXC20P: {
		Name:      EncXC20P,
		Support:   SupportCustom, // Requires custom implementation
		KeySize:   32,
		NonceSize: 24,
		TagSize:   16,
	},
	EncA128GCM: {
		Name:      EncA128GCM,
		Support:   SupportNative,
		KeySize:   16,
		NonceSize: 12,
		TagSize:   16,
	},
	EncA128CBCHS256: {
		Name:      EncA128CBCHS256,
		Support:   SupportNative,
		KeySize:   32, // 16 for AES + 16 for HMAC
		NonceSize: 16,
		TagSize:   16,
	},
}

// GetKeyAlgorithmInfo returns information about a key agreement algorithm.
func GetKeyAlgorithmInfo(alg string) (KeyAlgorithmInfo, bool) {
	info, ok := keyAlgorithms[alg]
	if !ok {
		return KeyAlgorithmInfo{
			Name:    alg,
			Support: SupportUnknown,
		}, false
	}
	return info, true
}

// GetContentAlgorithmInfo returns information about a content encryption algorithm.
func GetContentAlgorithmInfo(enc string) (ContentAlgorithmInfo, bool) {
	info, ok := contentAlgorithms[enc]
	if !ok {
		return ContentAlgorithmInfo{
			Name:    enc,
			Support: SupportUnknown,
		}, false
	}
	return info, true
}

// DIDCommAnoncryptDefaults returns the default algorithms for DIDComm anoncrypt.
func DIDCommAnoncryptDefaults() (keyAlg string, contentAlg string) {
	return AlgECDHESA256KW, EncXC20P
}

// DIDCommAuthcryptDefaults returns the default algorithms for DIDComm authcrypt.
func DIDCommAuthcryptDefaults() (keyAlg string, contentAlg string) {
	return AlgECDH1PUA256KW, EncA256CBCHS512
}

// InteropSafeAnoncryptDefaults returns anoncrypt algorithms that work with jwx natively.
// Use these for immediate interoperability before XC20P is implemented.
func InteropSafeAnoncryptDefaults() (keyAlg string, contentAlg string) {
	return AlgECDHESA256KW, EncA256GCM
}

// GenerateContentEncryptionKey generates a random key for the specified content encryption algorithm.
func GenerateContentEncryptionKey(enc string) ([]byte, error) {
	info, ok := GetContentAlgorithmInfo(enc)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, enc)
	}

	key := make([]byte, info.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}
