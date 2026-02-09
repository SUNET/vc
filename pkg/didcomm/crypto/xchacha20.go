//go:build didcomm && vc20

package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Poly1305 implements the XC20P content encryption algorithm
// as used in DIDComm v2.1 for anonymous encryption (anoncrypt).
//
// XChaCha20-Poly1305 is the default content encryption algorithm for
// DIDComm anoncrypt. It uses a 256-bit key and a 192-bit (24-byte) nonce,
// which allows for safe random nonce generation without risk of collision.
//
// References:
//   - RFC 8439 (ChaCha20-Poly1305)
//   - draft-irtf-cfrg-xchacha (XChaCha20-Poly1305)
//   - DIDComm v2.1 Specification

const (
	// XC20PKeySize is the key size for XChaCha20-Poly1305 (256 bits)
	XC20PKeySize = chacha20poly1305.KeySize // 32 bytes

	// XC20PNonceSize is the nonce size for XChaCha20-Poly1305 (192 bits)
	XC20PNonceSize = chacha20poly1305.NonceSizeX // 24 bytes

	// XC20PTagSize is the authentication tag size (128 bits)
	XC20PTagSize = 16
)

// XC20PAEAD wraps the XChaCha20-Poly1305 AEAD cipher for DIDComm use.
type XC20PAEAD struct {
	aead cipher.AEAD
}

// NewXC20P creates a new XChaCha20-Poly1305 AEAD instance.
// The key must be exactly 32 bytes (256 bits).
func NewXC20P(key []byte) (*XC20PAEAD, error) {
	if len(key) != XC20PKeySize {
		return nil, fmt.Errorf("%w: XC20P key must be %d bytes, got %d",
			ErrInvalidKey, XC20PKeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &XC20PAEAD{aead: aead}, nil
}

// Encrypt encrypts plaintext with additional authenticated data (AAD).
// Returns the ciphertext with the authentication tag appended.
// A random nonce is generated and prepended to the ciphertext.
//
// Output format: nonce (24 bytes) || ciphertext || tag (16 bytes)
func (x *XC20PAEAD) Encrypt(plaintext, aad []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, XC20PNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return x.EncryptWithNonce(nonce, plaintext, aad)
}

// EncryptWithNonce encrypts plaintext using a specific nonce.
// This is useful for deterministic testing or when the nonce is
// derived from other data.
//
// Output format: nonce (24 bytes) || ciphertext || tag (16 bytes)
func (x *XC20PAEAD) EncryptWithNonce(nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != XC20PNonceSize {
		return nil, fmt.Errorf("%w: XC20P nonce must be %d bytes, got %d",
			ErrInvalidNonce, XC20PNonceSize, len(nonce))
	}

	// Seal appends the ciphertext to dst
	// Result: nonce || ciphertext || tag
	ciphertext := x.aead.Seal(nonce, nonce, plaintext, aad)

	return ciphertext, nil
}

// EncryptSeparate encrypts plaintext and returns ciphertext and tag separately.
// This is useful for JWE construction where ciphertext and tag are separate fields.
func (x *XC20PAEAD) EncryptSeparate(nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(nonce) != XC20PNonceSize {
		return nil, nil, fmt.Errorf("%w: XC20P nonce must be %d bytes, got %d",
			ErrInvalidNonce, XC20PNonceSize, len(nonce))
	}

	// Seal: result = ciphertext || tag
	sealed := x.aead.Seal(nil, nonce, plaintext, aad)

	// Split into ciphertext and tag
	if len(sealed) < XC20PTagSize {
		return nil, nil, fmt.Errorf("encrypted output too short")
	}
	ciphertext = sealed[:len(sealed)-XC20PTagSize]
	tag = sealed[len(sealed)-XC20PTagSize:]

	return ciphertext, tag, nil
}

// DecryptSeparate decrypts ciphertext with a separate tag.
// This is useful for JWE decryption where ciphertext and tag are separate fields.
func (x *XC20PAEAD) DecryptSeparate(nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(nonce) != XC20PNonceSize {
		return nil, fmt.Errorf("%w: XC20P nonce must be %d bytes, got %d",
			ErrInvalidNonce, XC20PNonceSize, len(nonce))
	}
	if len(tag) != XC20PTagSize {
		return nil, fmt.Errorf("%w: XC20P tag must be %d bytes, got %d",
			ErrVerificationFailed, XC20PTagSize, len(tag))
	}

	// Combine ciphertext and tag for Open
	sealed := append(ciphertext, tag...)

	plaintext, err := x.aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt.
// The input should be: nonce (24 bytes) || ciphertext || tag (16 bytes)
func (x *XC20PAEAD) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < XC20PNonceSize+XC20PTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryptionFailed)
	}

	// Extract nonce from the beginning
	nonce := ciphertext[:XC20PNonceSize]
	encryptedData := ciphertext[XC20PNonceSize:]

	return x.DecryptWithNonce(nonce, encryptedData, aad)
}

// DecryptWithNonce decrypts ciphertext using a specific nonce.
// The ciphertext should NOT include the nonce prefix.
// Input format: ciphertext || tag (16 bytes)
func (x *XC20PAEAD) DecryptWithNonce(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != XC20PNonceSize {
		return nil, fmt.Errorf("%w: XC20P nonce must be %d bytes, got %d",
			ErrInvalidNonce, XC20PNonceSize, len(nonce))
	}

	if len(ciphertext) < XC20PTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short for tag", ErrDecryptionFailed)
	}

	plaintext, err := x.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// KeySize returns the required key size in bytes.
func (x *XC20PAEAD) KeySize() int {
	return XC20PKeySize
}

// NonceSize returns the required nonce size in bytes.
func (x *XC20PAEAD) NonceSize() int {
	return XC20PNonceSize
}

// Overhead returns the maximum difference between plaintext and ciphertext lengths.
func (x *XC20PAEAD) Overhead() int {
	return x.aead.Overhead()
}

// ContentEncryptor is an interface for content encryption algorithms.
type ContentEncryptor interface {
	// Encrypt encrypts plaintext with AAD, generating a random nonce
	Encrypt(plaintext, aad []byte) ([]byte, error)

	// EncryptWithNonce encrypts plaintext with a specific nonce
	EncryptWithNonce(nonce, plaintext, aad []byte) ([]byte, error)

	// Decrypt decrypts ciphertext (with prepended nonce) using AAD
	Decrypt(ciphertext, aad []byte) ([]byte, error)

	// DecryptWithNonce decrypts ciphertext with a specific nonce
	DecryptWithNonce(nonce, ciphertext, aad []byte) ([]byte, error)

	// KeySize returns the required key size in bytes
	KeySize() int

	// NonceSize returns the required nonce size in bytes
	NonceSize() int

	// Overhead returns the authentication tag overhead
	Overhead() int
}

// Verify XC20PAEAD implements ContentEncryptor
var _ ContentEncryptor = (*XC20PAEAD)(nil)

// NewContentEncryptor creates a ContentEncryptor for the specified algorithm.
func NewContentEncryptor(algorithm string, key []byte) (ContentEncryptor, error) {
	switch algorithm {
	case EncXC20P:
		return NewXC20P(key)
	case EncA256GCM, EncA128GCM, EncA256CBCHS512, EncA128CBCHS256:
		// These are handled by jwx natively
		return nil, fmt.Errorf("%w: %s should be handled by jwx", ErrUnsupportedAlgorithm, algorithm)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}
