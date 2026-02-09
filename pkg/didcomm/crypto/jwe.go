//go:build didcomm && vc20

package crypto

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWEHeader represents the protected header of a JWE.
type JWEHeader struct {
	// Algorithm is the key agreement algorithm (e.g., ECDH-ES, ECDH-1PU)
	Algorithm string `json:"alg"`

	// Encryption is the content encryption algorithm (e.g., A256GCM, A256CBC-HS512)
	Encryption string `json:"enc"`

	// Type is the media type of the JWE (should be "didcomm-encrypted+json")
	Type string `json:"typ,omitempty"`

	// SenderKeyID is the sender's key ID (for ECDH-1PU authcrypt)
	SenderKeyID string `json:"skid,omitempty"`

	// AgreementPartyUInfo is the APU for ECDH (base64url-encoded sender DID)
	AgreementPartyUInfo string `json:"apu,omitempty"`

	// AgreementPartyVInfo is the APV for ECDH (base64url-encoded recipient DIDs hash)
	AgreementPartyVInfo string `json:"apv,omitempty"`
}

// EncryptionOptions configures encryption behavior.
type EncryptionOptions struct {
	// Algorithm is the key agreement algorithm. Default: ECDH-ES (anoncrypt)
	Algorithm string

	// Encryption is the content encryption algorithm. Default: A256GCM
	Encryption string

	// SenderKey is the sender's private key (required for ECDH-1PU authcrypt)
	SenderKey jwk.Key

	// SenderDID is the sender's DID (for APU)
	SenderDID string
}

// DefaultEncryptionOptions returns options for anonymous encryption (anoncrypt).
func DefaultEncryptionOptions() EncryptionOptions {
	return EncryptionOptions{
		Algorithm:  "ECDH-ES+A256KW",
		Encryption: "A256GCM",
	}
}

// AuthcryptOptions returns options for authenticated encryption (authcrypt).
func AuthcryptOptions(senderKey jwk.Key, senderDID string) EncryptionOptions {
	return EncryptionOptions{
		Algorithm:  "ECDH-1PU+A256KW",
		Encryption: "A256CBC-HS512",
		SenderKey:  senderKey,
		SenderDID:  senderDID,
	}
}

// Encrypt encrypts a plaintext message for the given recipients.
// Returns a JWE compact serialization or JSON serialization depending on recipient count.
func Encrypt(ctx context.Context, plaintext []byte, recipientKeys []jwk.Key, opts EncryptionOptions) ([]byte, error) {
	if len(recipientKeys) == 0 {
		return nil, ErrNoRecipients
	}

	// Determine algorithms
	keyAlg := jwa.ECDH_ES_A256KW()
	if opts.Algorithm != "" {
		var err error
		keyAlg, err = parseKeyAlgorithm(opts.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
		}
	}

	contentAlg := jwa.A256GCM()
	if opts.Encryption != "" {
		var err error
		contentAlg, err = parseContentAlgorithm(opts.Encryption)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
		}
	}

	// Build encryption options
	encOpts := []jwe.EncryptOption{
		jwe.WithContentEncryption(contentAlg),
	}

	// For multi-recipient, we need to use JSON serialization
	// (compact serialization only supports a single recipient)
	if len(recipientKeys) > 1 {
		encOpts = append(encOpts, jwe.WithJSON())
		for _, recipientKey := range recipientKeys {
			encOpts = append(encOpts, jwe.WithKey(keyAlg, recipientKey))
		}
	} else {
		encOpts = append(encOpts, jwe.WithKey(keyAlg, recipientKeys[0]))
	}

	// Encrypt
	encrypted, err := jwe.Encrypt(plaintext, encOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	return encrypted, nil
}

// Decrypt decrypts a JWE using the provided private key.
func Decrypt(ctx context.Context, encrypted []byte, privateKey jwk.Key) ([]byte, error) {
	plaintext, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey))
	if err != nil {
		// Try other algorithms
		plaintext, err = jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A128KW(), privateKey))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
	}

	return plaintext, nil
}

// DecryptWithKeyStore decrypts a JWE using a key store to find the appropriate key.
func DecryptWithKeyStore(ctx context.Context, encrypted []byte, keyStore KeyStore) ([]byte, error) {
	// Parse the JWE to get recipient information
	msg, err := jwe.Parse(encrypted)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWE: %v", ErrInvalidJWE, err)
	}

	// Try each recipient
	for _, recipient := range msg.Recipients() {
		headers := recipient.Headers()
		var kid string
		if err := headers.Get("kid", &kid); err != nil {
			continue
		}

		privateKey, err := keyStore.GetPrivateKey(ctx, kid)
		if err != nil {
			continue
		}

		plaintext, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey))
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("%w: no matching key found", ErrRecipientNotFound)
}

// EncryptedMessage represents a DIDComm encrypted message (JWE).
type EncryptedMessage struct {
	// Protected is the base64url-encoded protected header
	Protected string `json:"protected"`

	// Recipients contains per-recipient encrypted key material
	Recipients []Recipient `json:"recipients"`

	// IV is the initialization vector (base64url-encoded)
	IV string `json:"iv"`

	// Ciphertext is the encrypted content (base64url-encoded)
	Ciphertext string `json:"ciphertext"`

	// Tag is the authentication tag (base64url-encoded)
	Tag string `json:"tag"`

	// AAD is additional authenticated data (base64url-encoded), optional
	AAD string `json:"aad,omitempty"`
}

// Recipient represents a JWE recipient.
type Recipient struct {
	// Header contains per-recipient unprotected header
	Header RecipientHeader `json:"header"`

	// EncryptedKey is the encrypted content encryption key (base64url-encoded)
	EncryptedKey string `json:"encrypted_key"`
}

// RecipientHeader contains per-recipient JWE header parameters.
type RecipientHeader struct {
	// KeyID identifies the recipient's key
	KeyID string `json:"kid"`

	// EphemeralPublicKey is the sender's ephemeral public key
	EphemeralPublicKey json.RawMessage `json:"epk,omitempty"`
}

// KeyStore provides access to private keys for decryption.
type KeyStore interface {
	// GetPrivateKey retrieves a private key by key ID
	GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error)

	// ListKeyIDs returns all available key IDs
	ListKeyIDs(ctx context.Context) ([]string, error)
}

// parseKeyAlgorithm converts a string algorithm name to jwa.KeyAlgorithm.
func parseKeyAlgorithm(alg string) (jwa.KeyEncryptionAlgorithm, error) {
	switch alg {
	case "ECDH-ES", "ECDH-ES+A256KW":
		return jwa.ECDH_ES_A256KW(), nil
	case "ECDH-ES+A128KW":
		return jwa.ECDH_ES_A128KW(), nil
	case "ECDH-1PU", "ECDH-1PU+A256KW":
		// ECDH-1PU is not directly supported by jwx, needs custom implementation
		return jwa.ECDH_ES_A256KW(), fmt.Errorf("ECDH-1PU not yet implemented")
	default:
		return jwa.ECDH_ES_A256KW(), fmt.Errorf("unknown algorithm: %s", alg)
	}
}

// parseContentAlgorithm converts a string algorithm name to jwa.ContentEncryptionAlgorithm.
func parseContentAlgorithm(enc string) (jwa.ContentEncryptionAlgorithm, error) {
	switch enc {
	case "A256GCM":
		return jwa.A256GCM(), nil
	case "A256CBC-HS512":
		return jwa.A256CBC_HS512(), nil
	case "A128GCM":
		return jwa.A128GCM(), nil
	default:
		return jwa.A256GCM(), fmt.Errorf("unknown encryption: %s", enc)
	}
}
