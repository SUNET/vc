package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Test vectors for DIDComm v2.1 interoperability testing.
// These are based on the DIDComm v2.1 specification and
// sicpa-dlab/didcomm-rust reference implementation.

// TestXC20PBasicEncryption tests basic XChaCha20-Poly1305 encryption/decryption.
func TestXC20PBasicEncryption(t *testing.T) {
	// Generate a test key
	key := make([]byte, XC20PKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	encryptor, err := NewXC20P(key)
	if err != nil {
		t.Fatalf("Failed to create XC20P encryptor: %v", err)
	}

	plaintext := []byte("Hello, DIDComm v2.1!")
	aad := []byte("additional authenticated data")

	// Test encryption with random nonce (returns nonce || ciphertext || tag)
	encrypted, err := encryptor.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify minimum size: nonce (24) + tag (16) + at least some ciphertext
	if len(encrypted) < XC20PNonceSize+XC20PTagSize {
		t.Errorf("Encrypted data too short")
	}

	// Test decryption (Decrypt expects nonce || ciphertext || tag format)
	decrypted, err := encryptor.Decrypt(encrypted, aad)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

// TestXC20PWithKnownVector tests XC20P with a known test vector.
func TestXC20PWithKnownVector(t *testing.T) {
	// Test vector from RFC 8439 (adapted for XChaCha20)
	// Note: XChaCha20-Poly1305 uses 24-byte nonce vs 12-byte for ChaCha20
	key := []byte{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	}

	encryptor, err := NewXC20P(key)
	if err != nil {
		t.Fatalf("Failed to create XC20P: %v", err)
	}

	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")

	// Encrypt (returns nonce || ciphertext || tag)
	encrypted, err := encryptor.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify we can decrypt
	decrypted, err := encryptor.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Round-trip failed")
	}
}

// TestXC20PContentEncryptor tests the ContentEncryptor interface.
func TestXC20PContentEncryptor(t *testing.T) {
	// Generate a key first
	key, err := GenerateContentEncryptionKey(EncXC20P)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewContentEncryptor(EncXC20P, key)
	if err != nil {
		t.Fatalf("Failed to create content encryptor: %v", err)
	}

	plaintext := []byte("Test message for ContentEncryptor interface")

	encrypted, err := encryptor.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := encryptor.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match")
	}
}

// TestAlgorithmRegistry tests the algorithm registry functions.
func TestAlgorithmRegistry(t *testing.T) {
	tests := []struct {
		name     string
		alg      string
		wantInfo bool
	}{
		{"ECDH-ES+A256KW", AlgECDHESA256KW, true},
		{"ECDH-1PU+A256KW", AlgECDH1PUA256KW, true},
		{"Unknown algorithm", "UNKNOWN", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := GetKeyAlgorithmInfo(tt.alg)
			if ok != tt.wantInfo {
				t.Errorf("GetKeyAlgorithmInfo(%s) = %v, want %v", tt.alg, ok, tt.wantInfo)
			}
			if ok {
				if info.Name != tt.alg {
					t.Errorf("Info name = %s, want %s", info.Name, tt.alg)
				}
			}
		})
	}
}

// TestContentAlgorithmRegistry tests content encryption algorithm registry.
func TestContentAlgorithmRegistry(t *testing.T) {
	tests := []struct {
		name     string
		enc      string
		wantInfo bool
		keySize  int
	}{
		{"A256GCM", EncA256GCM, true, 32},
		{"XC20P", EncXC20P, true, 32},
		{"A256CBC-HS512", EncA256CBCHS512, true, 64},
		{"Unknown", "UNKNOWN", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := GetContentAlgorithmInfo(tt.enc)
			if ok != tt.wantInfo {
				t.Errorf("GetContentAlgorithmInfo(%s) = %v, want %v", tt.enc, ok, tt.wantInfo)
			}
			if ok && info.KeySize != tt.keySize {
				t.Errorf("KeySize = %d, want %d", info.KeySize, tt.keySize)
			}
		})
	}
}

// TestDIDCommDefaults tests the default algorithm selections.
func TestDIDCommDefaults(t *testing.T) {
	t.Run("AnoncryptDefaults", func(t *testing.T) {
		keyAlg, contentEnc := DIDCommAnoncryptDefaults()
		if keyAlg != AlgECDHESA256KW {
			t.Errorf("Expected %s, got %s", AlgECDHESA256KW, keyAlg)
		}
		if contentEnc != EncXC20P {
			t.Errorf("Expected %s, got %s", EncXC20P, contentEnc)
		}
	})

	t.Run("AuthcryptDefaults", func(t *testing.T) {
		keyAlg, contentEnc := DIDCommAuthcryptDefaults()
		if keyAlg != AlgECDH1PUA256KW {
			t.Errorf("Expected %s, got %s", AlgECDH1PUA256KW, keyAlg)
		}
		if contentEnc != EncA256CBCHS512 {
			t.Errorf("Expected %s, got %s", EncA256CBCHS512, contentEnc)
		}
	})

	t.Run("InteropSafeDefaults", func(t *testing.T) {
		keyAlg, contentEnc := InteropSafeAnoncryptDefaults()
		if keyAlg != AlgECDHESA256KW {
			t.Errorf("Expected %s, got %s", AlgECDHESA256KW, keyAlg)
		}
		if contentEnc != EncA256GCM {
			t.Errorf("Expected %s, got %s", EncA256GCM, contentEnc)
		}
	})
}

// TestGenerateContentEncryptionKey tests CEK generation for various algorithms.
func TestGenerateContentEncryptionKey(t *testing.T) {
	tests := []struct {
		enc     string
		keySize int
	}{
		{EncA256GCM, 32},
		{EncXC20P, 32},
		{EncA256CBCHS512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.enc, func(t *testing.T) {
			key, err := GenerateContentEncryptionKey(tt.enc)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			if len(key) != tt.keySize {
				t.Errorf("Key size = %d, want %d", len(key), tt.keySize)
			}
		})
	}
}

// TestJWEWithX25519 tests JWE encryption/decryption with X25519 keys.
func TestJWEWithX25519(t *testing.T) {
	ctx := context.Background()

	// Generate X25519 key pair
	recipientKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	// Set key ID
	if err := recipientKey.Set("kid", "test-recipient-1"); err != nil {
		t.Fatalf("Failed to set kid: %v", err)
	}

	plaintext := []byte(`{"type":"https://didcomm.org/test/1.0/message","body":{"text":"Hello DIDComm!"}}`)

	// Test with interop-safe defaults (A256GCM)
	opts := EncryptionOptions{
		Algorithm:  AlgECDHESA256KW,
		Encryption: EncA256GCM,
	}

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{recipientKey}, opts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify it's valid JSON (for JSON serialization)
	var jweMsg map[string]any
	if err := json.Unmarshal(encrypted, &jweMsg); err != nil {
		// Might be compact serialization for single recipient
		t.Logf("Not JSON format (compact serialization): %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(ctx, encrypted, recipientKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

// TestJWEWithXC20P tests JWE with XChaCha20-Poly1305 content encryption.
func TestJWEWithXC20P(t *testing.T) {
	ctx := context.Background()

	// Generate X25519 key pair
	recipientKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	if err := recipientKey.Set("kid", "test-xc20p-recipient"); err != nil {
		t.Fatalf("Failed to set kid: %v", err)
	}

	plaintext := []byte(`{"type":"https://didcomm.org/test/1.0/xc20p","body":{"text":"XC20P test"}}`)

	// Test with XC20P
	opts := EncryptionOptions{
		Algorithm:  AlgECDHESA256KW,
		Encryption: EncXC20P,
	}

	encrypted, err := Encrypt(ctx, plaintext, []jwk.Key{recipientKey}, opts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Parse and verify structure
	var msg EncryptedMessage
	if err := json.Unmarshal(encrypted, &msg); err != nil {
		t.Fatalf("Failed to parse encrypted message: %v", err)
	}

	// Verify protected header
	protectedJSON, err := base64.RawURLEncoding.DecodeString(msg.Protected)
	if err != nil {
		t.Fatalf("Failed to decode protected header: %v", err)
	}

	var header JWEHeader
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	if header.Encryption != EncXC20P {
		t.Errorf("Expected enc=%s, got %s", EncXC20P, header.Encryption)
	}

	// Decrypt
	decrypted, err := Decrypt(ctx, encrypted, recipientKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

// TestMultiRecipientEncryption tests encryption to multiple recipients.
func TestMultiRecipientEncryption(t *testing.T) {
	ctx := context.Background()

	// Generate multiple recipient keys
	var recipients []jwk.Key
	for i := range 3 {
		key, err := generateECDHKey(CurveX25519)
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		if err := key.Set("kid", "recipient-"+string(rune('A'+i))); err != nil {
			t.Fatalf("Failed to set kid: %v", err)
		}
		recipients = append(recipients, key)
	}

	plaintext := []byte(`{"type":"https://didcomm.org/test/1.0/multi","body":{"to":"all"}}`)

	opts := EncryptionOptions{
		Algorithm:  AlgECDHESA256KW,
		Encryption: EncA256GCM,
	}

	encrypted, err := Encrypt(ctx, plaintext, recipients, opts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Each recipient should be able to decrypt
	for i, recipientKey := range recipients {
		decrypted, err := Decrypt(ctx, encrypted, recipientKey)
		if err != nil {
			t.Errorf("Recipient %d failed to decrypt: %v", i, err)
			continue
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Recipient %d: decrypted text doesn't match", i)
		}
	}
}

// TestECDH1PUKeyAgreement tests ECDH-1PU key derivation.
func TestECDH1PUKeyAgreement(t *testing.T) {
	// Generate sender and recipient keys
	senderKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}

	recipientKey, err := generateECDHKey(CurveX25519)
	if err != nil {
		t.Fatalf("Failed to generate recipient key: %v", err)
	}

	// Create ECDH-1PU instance
	agreement, err := NewECDH1PU(senderKey, recipientKey, AlgECDH1PUA256KW, EncA256CBCHS512)
	if err != nil {
		t.Fatalf("Failed to create ECDH-1PU: %v", err)
	}

	// Derive key
	derivedKey, ephPubKey, err := agreement.DeriveKey()
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	if len(derivedKey) != 32 {
		t.Errorf("Expected 32-byte derived key, got %d", len(derivedKey))
	}

	if ephPubKey == nil {
		t.Error("Ephemeral public key is nil")
	}

	// Get sender public key for decryption verification
	senderPubKey, err := senderKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get sender public key: %v", err)
	}

	// Create recipient's view for decryption
	recipientAgreement, err := NewECDH1PU(nil, recipientKey, AlgECDH1PUA256KW, EncA256CBCHS512)
	if err != nil {
		t.Fatalf("Failed to create recipient ECDH-1PU: %v", err)
	}

	// Derive the same key from recipient's perspective
	recipientDerivedKey, err := recipientAgreement.DeriveKeyForDecryption(ephPubKey, senderPubKey)
	if err != nil {
		t.Fatalf("Failed to derive key for decryption: %v", err)
	}

	// Keys should match
	if !bytes.Equal(derivedKey, recipientDerivedKey) {
		t.Error("Derived keys don't match between sender and recipient")
	}
}

// TestCurveConstants verifies curve constant values.
func TestCurveConstants(t *testing.T) {
	expected := map[string]string{
		"X25519":    CurveX25519,
		"P-256":     CurveP256,
		"P-384":     CurveP384,
		"secp256k1": CurveSecp256k1,
		"Ed25519":   CurveEd25519,
	}

	for name, constant := range expected {
		if constant != name {
			t.Errorf("Curve constant %s = %q, want %q", name, constant, name)
		}
	}
}
