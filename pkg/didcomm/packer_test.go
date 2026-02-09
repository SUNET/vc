//go:build didcomm && vc20

package didcomm

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"vc/pkg/didcomm/crypto"
	"vc/pkg/didcomm/message"
)

func TestPackPlaintext(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"hello": "world"}),
	)

	result, err := PackPlaintext(msg)
	if err != nil {
		t.Fatalf("PackPlaintext() error = %v", err)
	}

	if result.MediaType != MediaTypePlaintext {
		t.Errorf("MediaType = %v, want %v", result.MediaType, MediaTypePlaintext)
	}

	if len(result.Message) == 0 {
		t.Error("expected non-empty message")
	}
}

func TestPackPlaintext_Invalid(t *testing.T) {
	msg := &message.Message{} // Missing required fields

	_, err := PackPlaintext(msg)
	if err == nil {
		t.Error("expected error for invalid message")
	}
}

func TestDetectMediaType(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "plaintext message",
			data:     `{"id":"123","type":"https://example.com/test"}`,
			expected: MediaTypePlaintext,
		},
		{
			name:     "JWE JSON",
			data:     `{"protected":"eyJ...","recipients":[],"iv":"...","ciphertext":"...","tag":"..."}`,
			expected: MediaTypeEncrypted,
		},
		{
			name:     "JWS JSON",
			data:     `{"payload":"eyJ...","signatures":[]}`,
			expected: MediaTypeSigned,
		},
		{
			name:     "compact JWS",
			data:     "eyJhbGciOiJFZERTQSJ9.eyJpZCI6IjEyMyJ9.signature",
			expected: MediaTypeSigned,
		},
		{
			name:     "compact JWE",
			data:     "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.encrypted_key.iv.ciphertext.tag",
			expected: MediaTypeEncrypted,
		},
		{
			name:     "unknown",
			data:     "random data",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectMediaType([]byte(tt.data))
			if result != tt.expected {
				t.Errorf("detectMediaType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUnpack_Plaintext(t *testing.T) {
	// Create and pack a plaintext message
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"hello": "world"}),
	)

	packed, err := PackPlaintext(msg)
	if err != nil {
		t.Fatalf("PackPlaintext() error = %v", err)
	}

	// Unpack
	result, err := Unpack(context.Background(), packed.Message, UnpackOptions{})
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if result.WasEncrypted {
		t.Error("expected WasEncrypted = false")
	}
	if result.WasSigned {
		t.Error("expected WasSigned = false")
	}
	if result.Message.ID != msg.ID {
		t.Errorf("Message.ID = %v, want %v", result.Message.ID, msg.ID)
	}
	if result.Message.Type != msg.Type {
		t.Errorf("Message.Type = %v, want %v", result.Message.Type, msg.Type)
	}
}

func TestUnpack_ExpectEncrypted(t *testing.T) {
	// Create a plaintext message
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
	)

	packed, _ := PackPlaintext(msg)

	// Unpack expecting encryption should fail
	_, err := Unpack(context.Background(), packed.Message, UnpackOptions{
		ExpectEncrypted: true,
	})
	if err == nil {
		t.Error("expected error when expecting encryption but message is plaintext")
	}
}

// Helper function to generate Ed25519 key pair as JWK
func generateEd25519KeyPair(t *testing.T, kid string) (jwk.Key, jwk.Key) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	privateJWK, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("Failed to import private key: %v", err)
	}
	_ = privateJWK.Set("kid", kid)

	publicJWK, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("Failed to import public key: %v", err)
	}
	_ = publicJWK.Set("kid", kid)

	return privateJWK, publicJWK
}

// Helper function to generate X25519 key pair as JWK
func generateX25519KeyPair(t *testing.T, kid string) (jwk.Key, jwk.Key) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	privateJWK, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("Failed to import X25519 private key: %v", err)
	}
	_ = privateJWK.Set("kid", kid)

	publicJWK, err := jwk.PublicKeyOf(privateJWK)
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	_ = publicJWK.Set("kid", kid)

	return privateJWK, publicJWK
}

// TestPackSigned tests signing a message.
func TestPackSigned(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"signed": true}),
	)

	privateKey, _ := generateEd25519KeyPair(t, "did:example:alice#key-1")

	result, err := PackSigned(context.Background(), msg, privateKey)
	if err != nil {
		t.Fatalf("PackSigned() error = %v", err)
	}

	if result.MediaType != MediaTypeSigned {
		t.Errorf("MediaType = %v, want %v", result.MediaType, MediaTypeSigned)
	}

	if len(result.Message) == 0 {
		t.Error("expected non-empty message")
	}
}

// TestPackAnoncrypt tests anonymous encryption (ECDH-ES).
func TestPackAnoncrypt(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"secret": "data"}),
	)

	_, recipientPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	result, err := PackAnoncrypt(context.Background(), msg, []jwk.Key{recipientPublicKey})
	if err != nil {
		t.Fatalf("PackAnoncrypt() error = %v", err)
	}

	if result.MediaType != MediaTypeEncrypted {
		t.Errorf("MediaType = %v, want %v", result.MediaType, MediaTypeEncrypted)
	}

	if len(result.ToKIDs) == 0 {
		t.Error("expected recipient KIDs")
	}
}

// TestPackAuthcrypt tests authenticated encryption (ECDH-1PU).
func TestPackAuthcrypt(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"authenticated": true}),
	)

	senderPrivateKey, _ := generateX25519KeyPair(t, "did:example:alice#key-1")
	_, recipientPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	result, err := PackAuthcrypt(context.Background(), msg, senderPrivateKey, []jwk.Key{recipientPublicKey})
	if err != nil {
		t.Fatalf("PackAuthcrypt() error = %v", err)
	}

	if result.MediaType != MediaTypeEncrypted {
		t.Errorf("MediaType = %v, want %v", result.MediaType, MediaTypeEncrypted)
	}
}

// TestPackAnoncrypt_RoundTrip tests encrypt/decrypt round trip with anoncrypt.
func TestPackAnoncrypt_RoundTrip(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"hello": "encrypted world"}),
	)

	recipientPrivateKey, recipientPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	// Encrypt
	packed, err := PackAnoncrypt(context.Background(), msg, []jwk.Key{recipientPublicKey})
	if err != nil {
		t.Fatalf("PackAnoncrypt() error = %v", err)
	}

	// Create a mock key store for decryption
	keyStore := &mockKeyStoreForPacker{
		keys: map[string]jwk.Key{
			"did:example:bob#key-1": recipientPrivateKey,
		},
	}

	// Unpack
	result, err := Unpack(context.Background(), packed.Message, UnpackOptions{
		KeyStore: keyStore,
	})
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if !result.WasEncrypted {
		t.Error("expected WasEncrypted = true")
	}

	if result.Message.ID != msg.ID {
		t.Errorf("Message.ID = %v, want %v", result.Message.ID, msg.ID)
	}

	if result.Message.Type != msg.Type {
		t.Errorf("Message.Type = %v, want %v", result.Message.Type, msg.Type)
	}
}

// TestPackAuthcrypt_RoundTrip tests encrypt/decrypt round trip with authcrypt.
// Note: This uses the crypto.DecryptECDH1PU function directly since authcrypt
// requires both the recipient's private key and sender's public key for decryption.
func TestPackAuthcrypt_RoundTrip(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"authenticated": "message"}),
	)

	senderPrivateKey, senderPublicKey := generateX25519KeyPair(t, "did:example:alice#key-1")
	recipientPrivateKey, recipientPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	// Encrypt
	packed, err := PackAuthcrypt(context.Background(), msg, senderPrivateKey, []jwk.Key{recipientPublicKey})
	if err != nil {
		t.Fatalf("PackAuthcrypt() error = %v", err)
	}

	// Decrypt using DecryptECDH1PU (which requires sender public key)
	decrypted, err := crypto.DecryptECDH1PU(context.Background(), packed.Message, recipientPrivateKey, senderPublicKey)
	if err != nil {
		t.Fatalf("DecryptECDH1PU() error = %v", err)
	}

	// Parse the decrypted message
	unpacked, err := message.Parse(decrypted)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if unpacked.ID != msg.ID {
		t.Errorf("Message.ID = %v, want %v", unpacked.ID, msg.ID)
	}

	if unpacked.Type != msg.Type {
		t.Errorf("Message.Type = %v, want %v", unpacked.Type, msg.Type)
	}
}

// TestPack_UnknownMode tests Pack with unknown encryption mode.
func TestPack_UnknownMode(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	_, recipientPublicKey := generateX25519KeyPair(t, "bob-key")

	_, err := Pack(context.Background(), msg, PackOptions{
		EncryptionMode: "unknown-mode",
		RecipientKeys:  []jwk.Key{recipientPublicKey},
	})

	if err == nil {
		t.Error("expected error for unknown encryption mode")
	}
}

// TestPack_AuthcryptWithoutSenderKey tests authcrypt without sender key.
func TestPack_AuthcryptWithoutSenderKey(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	_, recipientPublicKey := generateX25519KeyPair(t, "bob-key")

	_, err := Pack(context.Background(), msg, PackOptions{
		EncryptionMode: "authcrypt",
		RecipientKeys:  []jwk.Key{recipientPublicKey},
		// Missing SenderKey!
	})

	if err == nil {
		t.Error("expected error for authcrypt without sender key")
	}
}

// TestPack_InvalidMessage tests Pack with invalid message.
func TestPack_InvalidMessage(t *testing.T) {
	msg := &message.Message{} // Missing required fields

	_, err := Pack(context.Background(), msg, PackOptions{})
	if err == nil {
		t.Error("expected error for invalid message")
	}
}

// TestPack_SignThenEncrypt tests signing before encryption.
func TestPack_SignThenEncrypt(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/protocols/1.0/test"),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
	)

	signerKey, _ := generateEd25519KeyPair(t, "did:example:alice#sign-key")
	_, recipientPublicKey := generateX25519KeyPair(t, "did:example:bob#key-1")

	result, err := Pack(context.Background(), msg, PackOptions{
		SignBeforeEncrypt: true,
		SignerKey:         signerKey,
		EncryptionMode:    "anoncrypt",
		RecipientKeys:     []jwk.Key{recipientPublicKey},
	})

	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	// Result should be encrypted (outer layer)
	if result.MediaType != MediaTypeEncrypted {
		t.Errorf("MediaType = %v, want %v", result.MediaType, MediaTypeEncrypted)
	}
}

// TestUnpack_WithoutKeyStore tests unpacking encrypted message without key store.
func TestUnpack_WithoutKeyStore(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	_, recipientPublicKey := generateX25519KeyPair(t, "bob-key")

	packed, _ := PackAnoncrypt(context.Background(), msg, []jwk.Key{recipientPublicKey})

	_, err := Unpack(context.Background(), packed.Message, UnpackOptions{
		// No KeyStore provided
	})

	if err == nil {
		t.Error("expected error when unpacking encrypted message without key store")
	}
}

// TestUnpack_ExpectSigned tests expecting signed message.
func TestUnpack_ExpectSigned(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	packed, _ := PackPlaintext(msg)

	_, err := Unpack(context.Background(), packed.Message, UnpackOptions{
		ExpectSigned: true,
	})

	if err == nil {
		t.Error("expected error when expecting signed but message is plaintext")
	}
}

// TestDetectCompactFormat tests detection of compact JWS/JWE formats.
func TestDetectCompactFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "compact JWS (2 dots)",
			input:    "header.payload.signature",
			expected: MediaTypeSigned,
		},
		{
			name:     "compact JWE (4 dots)",
			input:    "header.encrypted_key.iv.ciphertext.tag",
			expected: MediaTypeEncrypted,
		},
		{
			name:     "no dots",
			input:    "plaintext",
			expected: "",
		},
		{
			name:     "one dot",
			input:    "header.payload",
			expected: "",
		},
		{
			name:     "three dots",
			input:    "a.b.c.d",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectCompactFormat([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("detectCompactFormat() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestPackPlaintext_WithKID tests that KID is not set for plaintext.
func TestPackPlaintext_WithKID(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
		message.WithFrom("did:example:alice"),
	)

	result, err := PackPlaintext(msg)
	if err != nil {
		t.Fatalf("PackPlaintext() error = %v", err)
	}

	// Plaintext messages should not have FromKID
	if result.FromKID != "" {
		t.Error("expected no FromKID for plaintext message")
	}
}

// TestPackSigned_ExtractsKID tests that signer KID is extracted.
func TestPackSigned_ExtractsKID(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	privateKey, _ := generateEd25519KeyPair(t, "did:example:alice#sign-key")

	result, err := PackSigned(context.Background(), msg, privateKey)
	if err != nil {
		t.Fatalf("PackSigned() error = %v", err)
	}

	if result.FromKID != "did:example:alice#sign-key" {
		t.Errorf("FromKID = %v, want did:example:alice#sign-key", result.FromKID)
	}
}

// TestPackAnoncrypt_ExtractsToKIDs tests that recipient KIDs are extracted.
func TestPackAnoncrypt_ExtractsToKIDs(t *testing.T) {
	msg := message.New(
		message.WithType("https://example.com/test"),
	)

	_, pub1 := generateX25519KeyPair(t, "did:example:bob#key-1")
	_, pub2 := generateX25519KeyPair(t, "did:example:carol#key-1")

	result, err := PackAnoncrypt(context.Background(), msg, []jwk.Key{pub1, pub2})
	if err != nil {
		t.Fatalf("PackAnoncrypt() error = %v", err)
	}

	if len(result.ToKIDs) != 2 {
		t.Errorf("len(ToKIDs) = %d, want 2", len(result.ToKIDs))
	}
}

// mockKeyStoreForPacker is a mock KeyStore for testing.
type mockKeyStoreForPacker struct {
	keys map[string]jwk.Key
}

func (m *mockKeyStoreForPacker) GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error) {
	if key, ok := m.keys[kid]; ok {
		return key, nil
	}
	return nil, crypto.ErrRecipientNotFound
}

func (m *mockKeyStoreForPacker) ListKeyIDs(ctx context.Context) ([]string, error) {
	var kids []string
	for kid := range m.keys {
		kids = append(kids, kid)
	}
	return kids, nil
}
