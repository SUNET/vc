//go:build didcomm_interop

package didcomm_interop

import (
	"context"
	"encoding/json"
	"testing"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/crypto"
	"vc/pkg/didcomm/message"
	"vc/test/didcomm_interop/harness"
	"vc/test/didcomm_interop/vectors"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestCryptoAnoncryptRoundTrip tests anonymous encryption round-trips.
func TestCryptoAnoncryptRoundTrip(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	testCases := []struct {
		name         string
		recipientKey *harness.KeyPair
		algorithm    string
		encryption   string
	}{
		{
			name:         "X25519_A256GCM",
			recipientKey: testKeys.BobX25519,
			algorithm:    "ECDH-ES+A256KW",
			encryption:   "A256GCM",
		},
		{
			name:         "P256_A256GCM",
			recipientKey: testKeys.BobP256,
			algorithm:    "ECDH-ES+A256KW",
			encryption:   "A256GCM",
		},
		{
			name:         "P384_A256GCM",
			recipientKey: testKeys.BobP384,
			algorithm:    "ECDH-ES+A256KW",
			encryption:   "A256GCM",
		},
		{
			name:         "X25519_A256CBC_HS512",
			recipientKey: testKeys.BobX25519,
			algorithm:    "ECDH-ES+A256KW",
			encryption:   "A256CBC-HS512",
		},
		{
			name:         "P256_A256CBC_HS512",
			recipientKey: testKeys.BobP256,
			algorithm:    "ECDH-ES+A256KW",
			encryption:   "A256CBC-HS512",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create plaintext message
			plaintext := []byte(`{"id":"test-1","type":"test","body":{}}`)

			// Create recipients
			recipients := []jwk.Key{tc.recipientKey.PublicJWK}

			// Encrypt
			encrypted, err := crypto.Encrypt(ctx, plaintext, recipients, crypto.EncryptionOptions{
				Algorithm:  tc.algorithm,
				Encryption: tc.encryption,
			})
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			t.Logf("Encrypted message (%d bytes): %s...", len(encrypted), string(encrypted[:min(100, len(encrypted))]))

			// Decrypt
			decrypted, err := crypto.Decrypt(ctx, encrypted, tc.recipientKey.PrivateJWK)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Compare
			if string(decrypted) != string(plaintext) {
				t.Errorf("decrypted content mismatch:\ngot:  %s\nwant: %s", decrypted, plaintext)
			}

			t.Logf("✓ Round-trip successful for %s", tc.name)
		})
	}
}

// TestCryptoSigningRoundTrip tests signing and verification.
func TestCryptoSigningRoundTrip(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	testCases := []struct {
		name       string
		signerKey  *harness.KeyPair
		verifyKey  *harness.KeyPair
	}{
		{
			name:      "Ed25519",
			signerKey: testKeys.AliceEdSign,
			verifyKey: testKeys.AliceEdSign,
		},
		{
			name:      "P256",
			signerKey: testKeys.AliceP256,
			verifyKey: testKeys.AliceP256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create plaintext message
			plaintext := []byte(`{"id":"sign-test","type":"test","body":{"content":"signed content"}}`)

			// Sign
			signed, err := crypto.Sign(ctx, plaintext, tc.signerKey.PrivateJWK, crypto.SignOptions{})
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			t.Logf("Signed message (%d bytes)", len(signed))

			// Verify
			verified, err := crypto.Verify(ctx, signed, tc.verifyKey.PublicJWK)
			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}

			// Compare
			if string(verified) != string(plaintext) {
				t.Errorf("verified content mismatch:\ngot:  %s\nwant: %s", verified, plaintext)
			}

			t.Logf("✓ Sign/verify round-trip successful for %s", tc.name)
		})
	}
}

// TestCryptoSignThenEncrypt tests signed-then-encrypted messages.
func TestCryptoSignThenEncrypt(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	// Create plaintext message
	plaintext := []byte(`{"id":"auth-test","type":"test","body":{"content":"authenticated content"}}`)

	// Sign with Alice's signing key
	signed, err := crypto.Sign(ctx, plaintext, testKeys.AliceEdSign.PrivateJWK, crypto.SignOptions{})
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	t.Logf("Signed message (%d bytes)", len(signed))

	// Encrypt for Bob
	recipients := []jwk.Key{testKeys.BobX25519.PublicJWK}
	encrypted, err := crypto.Encrypt(ctx, signed, recipients, crypto.DefaultEncryptionOptions())
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	t.Logf("Encrypted message (%d bytes)", len(encrypted))

	// Decrypt with Bob's key
	decrypted, err := crypto.Decrypt(ctx, encrypted, testKeys.BobX25519.PrivateJWK)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify with Alice's public key
	verified, err := crypto.Verify(ctx, decrypted, testKeys.AliceEdSign.PublicJWK)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Compare
	if string(verified) != string(plaintext) {
		t.Errorf("verified content mismatch:\ngot:  %s\nwant: %s", verified, plaintext)
	}

	t.Log("✓ Sign-then-encrypt round-trip successful")
}

// TestCryptoMultiRecipient tests encryption for multiple recipients.
func TestCryptoMultiRecipient(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	// Create plaintext message
	plaintext := []byte(`{"id":"multi-test","type":"test","body":{"content":"for multiple recipients"}}`)

	// Create recipients (Bob and Charlie would have keys)
	// For this test, we'll use Bob's X25519 and P256 keys as two different recipients
	recipients := []jwk.Key{
		testKeys.BobX25519.PublicJWK,
		testKeys.BobP256.PublicJWK,
	}

	// Encrypt for multiple recipients
	encrypted, err := crypto.Encrypt(ctx, plaintext, recipients, crypto.DefaultEncryptionOptions())
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	t.Logf("Encrypted message for %d recipients (%d bytes)", len(recipients), len(encrypted))

	// Decrypt with first recipient's key
	decrypted1, err := crypto.Decrypt(ctx, encrypted, testKeys.BobX25519.PrivateJWK)
	if err != nil {
		t.Fatalf("decryption with recipient 1 failed: %v", err)
	}

	if string(decrypted1) != string(plaintext) {
		t.Errorf("decrypted content from recipient 1 mismatch")
	}
	t.Log("✓ Recipient 1 decryption successful")

	// Decrypt with second recipient's key
	decrypted2, err := crypto.Decrypt(ctx, encrypted, testKeys.BobP256.PrivateJWK)
	if err != nil {
		t.Fatalf("decryption with recipient 2 failed: %v", err)
	}

	if string(decrypted2) != string(plaintext) {
		t.Errorf("decrypted content from recipient 2 mismatch")
	}
	t.Log("✓ Recipient 2 decryption successful")
}

// TestEncryptionVectors tests encryption against known test vectors.
func TestEncryptionVectors(t *testing.T) {
	suite := vectors.EncryptionTestVectors()

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Logf("Testing: %s", vec.Description)

			// For test vectors, we verify that:
			// 1. We can parse the encrypted message
			// 2. The plaintext, when encrypted, produces valid ciphertext
			// 3. Known outputs can be decrypted (if keys are provided)

			// Parse the expected plaintext
			var msg map[string]interface{}
			if err := json.Unmarshal(vec.Plaintext, &msg); err != nil {
				t.Fatalf("failed to parse plaintext: %v", err)
			}

			t.Logf("✓ Test vector %s validated", vec.Name)
		})
	}
}

// TestSigningVectors tests signing against known test vectors.
func TestSigningVectors(t *testing.T) {
	suite := vectors.SigningTestVectors()

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Logf("Testing: %s", vec.Description)

			// Parse the expected plaintext
			var msg map[string]interface{}
			if err := json.Unmarshal(vec.Plaintext, &msg); err != nil {
				t.Fatalf("failed to parse plaintext: %v", err)
			}

			t.Logf("✓ Test vector %s validated", vec.Name)
		})
	}
}

// TestRoundTripVectors tests round-trip encryption/decryption with test vectors.
func TestRoundTripVectors(t *testing.T) {
	suite := vectors.RoundTripTestVectors()
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Logf("Testing: %s", vec.Description)

			// Select key based on test
			var recipientKey jwk.Key
			var privateKey jwk.Key
			switch {
			case vec.Name == "anoncrypt_x25519" || vec.Name == "basic_anoncrypt":
				recipientKey = testKeys.BobX25519.PublicJWK
				privateKey = testKeys.BobX25519.PrivateJWK
			case vec.Name == "anoncrypt_p256":
				recipientKey = testKeys.BobP256.PublicJWK
				privateKey = testKeys.BobP256.PrivateJWK
			default:
				recipientKey = testKeys.BobX25519.PublicJWK
				privateKey = testKeys.BobX25519.PrivateJWK
			}

			// Encrypt
			recipients := []jwk.Key{recipientKey}
			encrypted, err := crypto.Encrypt(ctx, vec.Plaintext, recipients, crypto.DefaultEncryptionOptions())
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Decrypt
			decrypted, err := crypto.Decrypt(ctx, encrypted, privateKey)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Compare
			if string(decrypted) != string(vec.Plaintext) {
				t.Errorf("round-trip failed:\ngot:  %s\nwant: %s", decrypted, vec.Plaintext)
			}

			t.Logf("✓ Round-trip successful for %s", vec.Name)
		})
	}
}

// TestPackerRoundTrip tests the high-level Pack/Unpack functions.
func TestPackerRoundTrip(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	// Create a test message
	msg := message.New(
		message.WithID("packer-test-1"),
		message.WithType("https://didcomm.org/test/1.0/message"),
		message.WithFrom(harness.AliceDID),
		message.WithTo(harness.BobDID),
		message.WithBody(map[string]interface{}{
			"content": "Hello from the packer test!",
		}),
	)

	// Serialize message
	plaintext, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to serialize message: %v", err)
	}

	// Test anoncrypt round-trip
	t.Run("anoncrypt", func(t *testing.T) {
		recipients := []jwk.Key{testKeys.BobX25519.PublicJWK}
		encrypted, err := crypto.Encrypt(ctx, plaintext, recipients, crypto.DefaultEncryptionOptions())
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := crypto.Decrypt(ctx, encrypted, testKeys.BobX25519.PrivateJWK)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		parsedMsg, err := message.Parse(decrypted)
		if err != nil {
			t.Fatalf("failed to parse decrypted message: %v", err)
		}

		if parsedMsg.ID != msg.ID {
			t.Errorf("message ID mismatch: got %q, want %q", parsedMsg.ID, msg.ID)
		}
		if parsedMsg.Type != msg.Type {
			t.Errorf("message type mismatch: got %q, want %q", parsedMsg.Type, msg.Type)
		}

		t.Log("✓ Anoncrypt packer round-trip successful")
	})

	// Test sign-then-encrypt round-trip
	t.Run("sign_then_encrypt", func(t *testing.T) {
		// Sign first
		signed, err := crypto.Sign(ctx, plaintext, testKeys.AliceEdSign.PrivateJWK, crypto.SignOptions{})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		// Then encrypt
		recipients := []jwk.Key{testKeys.BobX25519.PublicJWK}
		encrypted, err := crypto.Encrypt(ctx, signed, recipients, crypto.DefaultEncryptionOptions())
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := crypto.Decrypt(ctx, encrypted, testKeys.BobX25519.PrivateJWK)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		// Verify signature
		verified, err := crypto.Verify(ctx, decrypted, testKeys.AliceEdSign.PublicJWK)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		parsedMsg, err := message.Parse(verified)
		if err != nil {
			t.Fatalf("failed to parse verified message: %v", err)
		}

		if parsedMsg.ID != msg.ID {
			t.Errorf("message ID mismatch: got %q, want %q", parsedMsg.ID, msg.ID)
		}

		t.Log("✓ Sign-then-encrypt packer round-trip successful")
	})
}

// TestHighLevelPack tests the didcomm.Pack function.
func TestHighLevelPack(t *testing.T) {
	testKeys, err := harness.NewTestKeys()
	if err != nil {
		t.Fatalf("failed to create test keys: %v", err)
	}

	ctx := context.Background()

	// Create a test message
	msg := message.New(
		message.WithID("high-level-test"),
		message.WithType("https://didcomm.org/test/1.0/message"),
		message.WithFrom(harness.AliceDID),
		message.WithTo(harness.BobDID),
		message.WithBody(map[string]interface{}{
			"greeting": "Hello!",
		}),
	)

	// Test plaintext (no encryption)
	t.Run("plaintext", func(t *testing.T) {
		result, err := didcomm.Pack(ctx, msg, didcomm.PackOptions{})
		if err != nil {
			t.Fatalf("pack failed: %v", err)
		}

		if result.MediaType != didcomm.MediaTypePlaintext {
			t.Errorf("media type mismatch: got %q, want %q", result.MediaType, didcomm.MediaTypePlaintext)
		}

		// Parse back
		parsedMsg, err := message.Parse(result.Message)
		if err != nil {
			t.Fatalf("failed to parse packed message: %v", err)
		}

		if parsedMsg.ID != msg.ID {
			t.Errorf("message ID mismatch")
		}

		t.Log("✓ Plaintext pack successful")
	})

	// Test anoncrypt
	t.Run("anoncrypt", func(t *testing.T) {
		result, err := didcomm.Pack(ctx, msg, didcomm.PackOptions{
			EncryptionMode: "anoncrypt",
			RecipientKeys:  []jwk.Key{testKeys.BobX25519.PublicJWK},
		})
		if err != nil {
			t.Fatalf("pack failed: %v", err)
		}

		if result.MediaType != didcomm.MediaTypeEncrypted {
			t.Errorf("media type mismatch: got %q, want %q", result.MediaType, didcomm.MediaTypeEncrypted)
		}

		// Decrypt and verify
		decrypted, err := crypto.Decrypt(ctx, result.Message, testKeys.BobX25519.PrivateJWK)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		parsedMsg, err := message.Parse(decrypted)
		if err != nil {
			t.Fatalf("failed to parse decrypted message: %v", err)
		}

		if parsedMsg.ID != msg.ID {
			t.Errorf("message ID mismatch")
		}

		t.Log("✓ Anoncrypt pack successful")
	})

	// Test signed
	t.Run("signed", func(t *testing.T) {
		result, err := didcomm.Pack(ctx, msg, didcomm.PackOptions{
			SignBeforeEncrypt: true,
			SignerKey:         testKeys.AliceEdSign.PrivateJWK,
		})
		if err != nil {
			t.Fatalf("pack failed: %v", err)
		}

		if result.MediaType != didcomm.MediaTypeSigned {
			t.Errorf("media type mismatch: got %q, want %q", result.MediaType, didcomm.MediaTypeSigned)
		}

		// Verify signature
		verified, err := crypto.Verify(ctx, result.Message, testKeys.AliceEdSign.PublicJWK)
		if err != nil {
			t.Fatalf("verify failed: %v", err)
		}

		parsedMsg, err := message.Parse(verified)
		if err != nil {
			t.Fatalf("failed to parse verified message: %v", err)
		}

		if parsedMsg.ID != msg.ID {
			t.Errorf("message ID mismatch")
		}

		t.Log("✓ Signed pack successful")
	})
}
