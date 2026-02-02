//go:build didcomm && vc20

package crypto

import "errors"

// Sentinel errors for cryptographic operations.
var (
	ErrEncryptionFailed     = errors.New("didcomm/crypto: encryption failed")
	ErrDecryptionFailed     = errors.New("didcomm/crypto: decryption failed")
	ErrSigningFailed        = errors.New("didcomm/crypto: signing failed")
	ErrVerificationFailed   = errors.New("didcomm/crypto: verification failed")
	ErrUnsupportedAlgorithm = errors.New("didcomm/crypto: unsupported algorithm")
	ErrInvalidKey           = errors.New("didcomm/crypto: invalid key")
	ErrNoRecipients         = errors.New("didcomm/crypto: no recipients specified")
	ErrRecipientNotFound    = errors.New("didcomm/crypto: recipient key not found")
	ErrInvalidJWE           = errors.New("didcomm/crypto: invalid JWE")
	ErrInvalidJWS           = errors.New("didcomm/crypto: invalid JWS")
)
