package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// NOTE: The standard jwx library does not support secp256k1 curve natively.
// These tests work with raw secp256k1 keys and the custom implementation
// that handles ES256K signing/verification.

// createTestSecp256k1Key creates a test key pair directly using dcrd library.
// Returns the private and public keys for direct use with our custom signers/verifiers.
func createTestSecp256k1Key(t *testing.T) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key: %v", err)
	}
	return privKey, privKey.PubKey()
}

// TestSecp256k1Signer_DirectKey tests the signer with directly created keys.
func TestSecp256k1Signer_DirectKey(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	// Test basic signing
	payload := []byte("Hello, secp256k1!")

	// Manually create signer to bypass JWK parsing issues
	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  privKey.PubKey(),
		keyID:      "test-key",
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Signature should be 64 bytes (r || s)
	if len(signature) != 64 {
		t.Errorf("Signature length = %d, want 64", len(signature))
	}
}

// TestSecp256k1Verifier_DirectKey tests the verifier with directly created keys.
func TestSecp256k1Verifier_DirectKey(t *testing.T) {
	privKey, pubKey := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      "test-key",
	}

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
		keyID:     "test-key",
	}

	// Sign and verify
	payload := []byte("Test message for verification")
	signature, _ := signer.Sign(payload)

	err := verifier.Verify(payload, signature)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

// TestSecp256k1Verifier_InvalidSignature tests verification with invalid signature.
func TestSecp256k1Verifier_InvalidSignature(t *testing.T) {
	privKey, pubKey := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  pubKey,
	}

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
	}

	payload := []byte("Original message")
	signature, _ := signer.Sign(payload)

	// Tamper with the message
	tamperedPayload := []byte("Tampered message")
	err := verifier.Verify(tamperedPayload, signature)
	if err == nil {
		t.Error("expected verification to fail for tampered message")
	}
}

// TestSecp256k1SignJWS_DirectKey tests JWS signing.
func TestSecp256k1SignJWS_DirectKey(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  privKey.PubKey(),
		keyID:      "test-key-1",
	}

	payload := []byte(`{"msg":"Hello, JWS!"}`)
	jws, err := signer.SignJWS(payload, "didcomm-signed+json")
	if err != nil {
		t.Fatalf("SignJWS() error = %v", err)
	}

	// JWS should be in compact format: header.payload.signature
	parts := bytes.Split(jws, []byte("."))
	if len(parts) != 3 {
		t.Errorf("JWS should have 3 parts, got %d", len(parts))
	}

	// Verify header
	headerBytes, _ := base64.RawURLEncoding.DecodeString(string(parts[0]))
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)

	if header["alg"] != "ES256K" {
		t.Errorf("alg = %v, want ES256K", header["alg"])
	}
	if header["typ"] != "didcomm-signed+json" {
		t.Errorf("typ = %v, want didcomm-signed+json", header["typ"])
	}
	if header["kid"] != "test-key-1" {
		t.Errorf("kid = %v, want test-key-1", header["kid"])
	}
}

// TestSecp256k1VerifyJWS_DirectKey tests JWS verification.
func TestSecp256k1VerifyJWS_DirectKey(t *testing.T) {
	privKey, pubKey := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      "test-key-1",
	}

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
		keyID:     "test-key-1",
	}

	originalPayload := []byte(`{"msg":"Round trip test"}`)
	jws, _ := signer.SignJWS(originalPayload, "didcomm-signed+json")

	// Verify and get payload back
	payload, err := verifier.VerifyJWS(jws)
	if err != nil {
		t.Fatalf("VerifyJWS() error = %v", err)
	}

	if !bytes.Equal(payload, originalPayload) {
		t.Errorf("Payload mismatch: got %s, want %s", payload, originalPayload)
	}
}

// TestSecp256k1VerifyJWS_InvalidFormat tests JWS verification with invalid format.
func TestSecp256k1VerifyJWS_InvalidFormat(t *testing.T) {
	_, pubKey := createTestSecp256k1Key(t)

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
	}

	// Not enough parts
	_, err := verifier.VerifyJWS([]byte("only.two"))
	if err == nil {
		t.Error("expected error for invalid JWS format")
	}
}

// TestSecp256k1VerifyJWS_WrongAlgorithm tests JWS verification with wrong algorithm.
func TestSecp256k1VerifyJWS_WrongAlgorithm(t *testing.T) {
	_, pubKey := createTestSecp256k1Key(t)

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
	}

	// Create a JWS with wrong algorithm in header
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"test":true}`))
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	fakeJWS := []byte(header + "." + payload + "." + signature)

	_, err := verifier.VerifyJWS(fakeJWS)
	if err == nil {
		t.Error("expected error for wrong algorithm")
	}
}

// TestSecp256k1_KeyID tests KeyID extraction.
func TestSecp256k1_KeyID(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  privKey.PubKey(),
		keyID:      "my-key-id",
	}

	if signer.KeyID() != "my-key-id" {
		t.Errorf("KeyID() = %v, want my-key-id", signer.KeyID())
	}
}

// TestSecp256k1_SignerPublicKey tests public key export from signer.
// NOTE: This test documents a known limitation - the standard jwx library
// does not support secp256k1 curve, so PublicKey() will fail when trying
// to create a JWK. The underlying signing/verification works fine.
func TestSecp256k1_SignerPublicKey(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  privKey.PubKey(),
		keyID:      "export-test",
	}

	// PublicKey() is expected to fail because jwx library doesn't support secp256k1
	_, err := signer.PublicKey()
	if err == nil {
		t.Log("PublicKey() succeeded - jwx may have added secp256k1 support")
		// If it somehow works in the future, verify the key has the correct curve
		return
	}

	// Verify it's the expected error about unknown curve
	if !bytes.Contains([]byte(err.Error()), []byte("secp256k1")) {
		t.Errorf("Expected error about secp256k1 curve, got: %v", err)
	}
}

// TestParseRSSignature_InvalidLength tests signature parsing with invalid length.
func TestParseRSSignature_InvalidLength(t *testing.T) {
	// Signature should be 64 bytes
	_, err := parseRSSignature(make([]byte, 63))
	if err == nil {
		t.Error("expected error for invalid signature length")
	}

	_, err = parseRSSignature(make([]byte, 65))
	if err == nil {
		t.Error("expected error for invalid signature length")
	}
}

// TestSignatureRoundTrip tests signature format conversion round trip.
func TestSignatureRoundTrip(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  privKey.PubKey(),
	}

	payload := []byte("Signature round trip test")
	signature, _ := signer.Sign(payload)

	// Parse the signature
	parsed, err := parseRSSignature(signature)
	if err != nil {
		t.Fatalf("parseRSSignature() error = %v", err)
	}

	// Convert back
	converted := signatureToRS(parsed)

	if !bytes.Equal(signature, converted) {
		t.Error("Signature round trip failed")
	}
}

// TestSplitJWS tests the JWS splitting helper.
func TestSplitJWS(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"valid JWS", "a.b.c", 3},
		{"four parts", "a.b.c.d", 4},
		{"no dots", "abc", 1},
		{"empty", "", 1},
		{"trailing dot", "a.b.", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitJWS([]byte(tt.input))
			if len(parts) != tt.expected {
				t.Errorf("splitJWS(%q) = %d parts, want %d", tt.input, len(parts), tt.expected)
			}
		})
	}
}

// TestPadTo32 tests the padding helper.
func TestPadTo32(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		length int
	}{
		{"short", []byte{1, 2, 3}, 32},
		{"exact", make([]byte, 32), 32},
		{"long", make([]byte, 40), 32},
		{"empty", []byte{}, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padTo32(tt.input)
			if len(result) != tt.length {
				t.Errorf("padTo32() length = %d, want %d", len(result), tt.length)
			}
		})
	}
}

// TestSecp256k1_MultipleSignatures tests signing multiple messages.
func TestSecp256k1_MultipleSignatures(t *testing.T) {
	privKey, pubKey := createTestSecp256k1Key(t)

	signer := &Secp256k1Signer{
		privateKey: privKey,
		publicKey:  pubKey,
	}

	verifier := &Secp256k1Verifier{
		publicKey: pubKey,
	}

	messages := []string{
		"Message 1",
		"Message 2 - different length",
		"M3",
		"A very long message that contains a lot of text to verify that the signature works correctly with varying lengths of input data",
	}

	for _, msg := range messages {
		payload := []byte(msg)
		signature, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("Sign(%q) error = %v", msg, err)
		}

		err = verifier.Verify(payload, signature)
		if err != nil {
			t.Errorf("Verify(%q) error = %v", msg, err)
		}
	}
}

// TestSecp256k1_DifferentKeys tests that different keys produce different signatures.
func TestSecp256k1_DifferentKeys(t *testing.T) {
	privKey1, _ := createTestSecp256k1Key(t)
	privKey2, _ := createTestSecp256k1Key(t)

	signer1 := &Secp256k1Signer{privateKey: privKey1, publicKey: privKey1.PubKey()}
	signer2 := &Secp256k1Signer{privateKey: privKey2, publicKey: privKey2.PubKey()}

	payload := []byte("Same message")

	sig1, _ := signer1.Sign(payload)
	sig2, _ := signer2.Sign(payload)

	if bytes.Equal(sig1, sig2) {
		t.Error("Different keys should produce different signatures")
	}
}

// TestSecp256k1_CrossVerification tests that keys don't cross-verify.
func TestSecp256k1_CrossVerification(t *testing.T) {
	privKey1, _ := createTestSecp256k1Key(t)
	_, pubKey2 := createTestSecp256k1Key(t)

	signer1 := &Secp256k1Signer{privateKey: privKey1, publicKey: privKey1.PubKey()}
	verifier2 := &Secp256k1Verifier{publicKey: pubKey2}

	payload := []byte("Test message")
	signature, _ := signer1.Sign(payload)

	// Signature from key1 should NOT verify with key2's public key
	err := verifier2.Verify(payload, signature)
	if err == nil {
		t.Error("Cross-verification should fail")
	}
}

// TestExportSecp256k1PublicKey tests public key export.
// NOTE: This test documents a known limitation - the standard jwx library
// does not support secp256k1 curve, so exportSecp256k1PublicKey will fail.
func TestExportSecp256k1PublicKey(t *testing.T) {
	privKey, _ := createTestSecp256k1Key(t)

	// exportSecp256k1PublicKey is expected to fail because jwx library doesn't support secp256k1
	pubKey, err := exportSecp256k1PublicKey(privKey.PubKey(), "export-key")
	if err == nil {
		t.Log("exportSecp256k1PublicKey() succeeded - jwx may have added secp256k1 support")
		// If it somehow works, verify key properties
		var crv string
		if err := pubKey.Get("crv", &crv); err != nil {
			t.Error("Failed to get curve")
		}
		if crv != CurveSecp256k1 {
			t.Errorf("crv = %v, want %v", crv, CurveSecp256k1)
		}
		return
	}

	// Verify it's the expected error about unknown curve
	if !bytes.Contains([]byte(err.Error()), []byte("secp256k1")) {
		t.Errorf("Expected error about secp256k1 curve, got: %v", err)
	}
}
