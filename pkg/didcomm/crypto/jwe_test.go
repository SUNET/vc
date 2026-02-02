//go:build didcomm && vc20

package crypto

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestEncryptDecrypt_ECDH_ES(t *testing.T) {
	// Generate X25519 key pair for recipient
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}

	// Convert to JWK
	recipientPrivateJWK, err := jwk.Import(recipientPrivate)
	if err != nil {
		t.Fatalf("failed to import recipient private key: %v", err)
	}
	if err := recipientPrivateJWK.Set("kid", "recipient-key-1"); err != nil {
		t.Fatalf("failed to set kid: %v", err)
	}

	recipientPublicJWK, err := jwk.Import(recipientPrivate.PublicKey())
	if err != nil {
		t.Fatalf("failed to import recipient public key: %v", err)
	}
	if err := recipientPublicJWK.Set("kid", "recipient-key-1"); err != nil {
		t.Fatalf("failed to set kid: %v", err)
	}

	// Encrypt
	plaintext := []byte(`{"id":"123","type":"https://example.com/test","body":{"message":"hello"}}`)
	encrypted, err := Encrypt(context.Background(), plaintext, []jwk.Key{recipientPublicJWK}, DefaultEncryptionOptions())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("expected non-empty encrypted message")
	}

	// Decrypt
	decrypted, err := Decrypt(context.Background(), encrypted, recipientPrivateJWK)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestEncrypt_NoRecipients(t *testing.T) {
	plaintext := []byte(`{"id":"123","type":"test"}`)

	_, err := Encrypt(context.Background(), plaintext, []jwk.Key{}, DefaultEncryptionOptions())
	if err != ErrNoRecipients {
		t.Errorf("expected ErrNoRecipients, got %v", err)
	}
}

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		hasError bool
	}{
		{"ECDH-ES", false},
		{"ECDH-ES+A256KW", false},
		{"ECDH-ES+A128KW", false},
		{"ECDH-1PU", true}, // Not yet implemented
		{"UNKNOWN", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseKeyAlgorithm(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("parseKeyAlgorithm() error = %v", err)
			}
		})
	}
}

func TestParseContentAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"A256GCM", "A256GCM", false},
		{"A256CBC-HS512", "A256CBC-HS512", false},
		{"A128GCM", "A128GCM", false},
		{"UNKNOWN", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			alg, err := parseContentAlgorithm(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("parseContentAlgorithm() error = %v", err)
			}

			if alg.String() != tt.expected {
				t.Errorf("algorithm = %v, want %v", alg.String(), tt.expected)
			}
		})
	}
}

func TestDefaultEncryptionOptions(t *testing.T) {
	opts := DefaultEncryptionOptions()

	if opts.Algorithm != "ECDH-ES+A256KW" {
		t.Errorf("Algorithm = %v, want ECDH-ES+A256KW", opts.Algorithm)
	}

	if opts.Encryption != "A256GCM" {
		t.Errorf("Encryption = %v, want A256GCM", opts.Encryption)
	}
}
