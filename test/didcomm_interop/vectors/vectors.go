// Package vectors provides test vector loading and validation for DIDComm interoperability tests.
package vectors

import (
	"encoding/json"
	"fmt"
)

// TestVector represents a single DIDComm test vector.
type TestVector struct {
	// Metadata
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"` // "encryption", "signing", "message", "protocol"

	// Input
	Plaintext      json.RawMessage `json:"plaintext,omitempty"`
	PlaintextData  []byte          `json:"-"` // Parsed plaintext
	SenderDID      string          `json:"sender_did,omitempty"`
	RecipientDID   string          `json:"recipient_did,omitempty"`
	RecipientKeyID string          `json:"recipient_key_id,omitempty"`
	SenderKeyID    string          `json:"sender_key_id,omitempty"`

	// Expected output (for validation)
	ExpectedJWE     string          `json:"expected_jwe,omitempty"`
	ExpectedJWS     string          `json:"expected_jws,omitempty"`
	ExpectedMessage json.RawMessage `json:"expected_message,omitempty"`

	// Cryptographic parameters
	Algorithm   string `json:"algorithm,omitempty"`   // e.g., "ECDH-ES+A256KW"
	Encryption  string `json:"encryption,omitempty"`  // e.g., "A256GCM"
	KeyCurve    string `json:"key_curve,omitempty"`   // e.g., "X25519", "P-256"
	SigningAlg  string `json:"signing_alg,omitempty"` // e.g., "EdDSA", "ES256"
	ContentType string `json:"content_type,omitempty"`

	// Flags
	IsAnoncrypt    bool   `json:"is_anoncrypt,omitempty"`
	IsAuthcrypt    bool   `json:"is_authcrypt,omitempty"`
	IsSigned       bool   `json:"is_signed,omitempty"`
	ExpectError    bool   `json:"expect_error,omitempty"`
	ExpectedErrMsg string `json:"expected_error,omitempty"`
}

// TestVectorSuite is a collection of related test vectors.
type TestVectorSuite struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Vectors     []*TestVector `json:"vectors"`
}

// EncryptionTestVectors returns test vectors for encryption operations.
func EncryptionTestVectors() *TestVectorSuite {
	return &TestVectorSuite{
		Name:        "encryption",
		Description: "DIDComm encryption test vectors",
		Vectors: []*TestVector{
			// Anoncrypt with X25519 + A256GCM
			{
				Name:           "anoncrypt_x25519_a256gcm",
				Description:    "Anonymous encryption with X25519 key agreement and A256GCM content encryption",
				Category:       "encryption",
				RecipientDID:   "did:example:bob",
				RecipientKeyID: "did:example:bob#key-x25519-1",
				Algorithm:      "ECDH-ES+A256KW",
				Encryption:     "A256GCM",
				KeyCurve:       "X25519",
				IsAnoncrypt:    true,
				Plaintext: json.RawMessage(`{
					"id": "test-message-1",
					"type": "https://example.org/test/1.0",
					"body": {"test": "data"}
				}`),
			},
			// Anoncrypt with P-256 + A256GCM
			{
				Name:           "anoncrypt_p256_a256gcm",
				Description:    "Anonymous encryption with P-256 key agreement and A256GCM content encryption",
				Category:       "encryption",
				RecipientDID:   "did:example:bob",
				RecipientKeyID: "did:example:bob#key-p256-1",
				Algorithm:      "ECDH-ES+A256KW",
				Encryption:     "A256GCM",
				KeyCurve:       "P-256",
				IsAnoncrypt:    true,
				Plaintext: json.RawMessage(`{
					"id": "test-message-2",
					"type": "https://example.org/test/1.0",
					"body": {"test": "p256 encryption"}
				}`),
			},
			// Authcrypt with X25519 + A256CBC-HS512
			{
				Name:           "authcrypt_x25519_a256cbc_hs512",
				Description:    "Authenticated encryption with X25519 key agreement and A256CBC-HS512",
				Category:       "encryption",
				SenderDID:      "did:example:alice",
				SenderKeyID:    "did:example:alice#key-x25519-1",
				RecipientDID:   "did:example:bob",
				RecipientKeyID: "did:example:bob#key-x25519-1",
				Algorithm:      "ECDH-1PU+A256KW",
				Encryption:     "A256CBC-HS512",
				KeyCurve:       "X25519",
				IsAuthcrypt:    true,
				Plaintext: json.RawMessage(`{
					"id": "test-message-3",
					"type": "https://example.org/test/1.0",
					"from": "did:example:alice",
					"body": {"test": "authenticated data"}
				}`),
			},
			// Authcrypt with P-256 + A256CBC-HS512
			{
				Name:           "authcrypt_p256_a256cbc_hs512",
				Description:    "Authenticated encryption with P-256 key agreement and A256CBC-HS512",
				Category:       "encryption",
				SenderDID:      "did:example:alice",
				SenderKeyID:    "did:example:alice#key-p256-1",
				RecipientDID:   "did:example:bob",
				RecipientKeyID: "did:example:bob#key-p256-1",
				Algorithm:      "ECDH-1PU+A256KW",
				Encryption:     "A256CBC-HS512",
				KeyCurve:       "P-256",
				IsAuthcrypt:    true,
				Plaintext: json.RawMessage(`{
					"id": "test-message-4",
					"type": "https://example.org/test/1.0",
					"from": "did:example:alice",
					"body": {"test": "P-256 authenticated data"}
				}`),
			},
		},
	}
}

// SigningTestVectors returns test vectors for signing operations.
func SigningTestVectors() *TestVectorSuite {
	return &TestVectorSuite{
		Name:        "signing",
		Description: "DIDComm signing test vectors",
		Vectors: []*TestVector{
			// EdDSA signing
			{
				Name:        "sign_eddsa",
				Description: "Sign message with EdDSA (Ed25519)",
				Category:    "signing",
				SenderDID:   "did:example:alice",
				SenderKeyID: "did:example:alice#key-ed25519-1",
				SigningAlg:  "EdDSA",
				IsSigned:    true,
				Plaintext: json.RawMessage(`{
					"id": "signed-message-1",
					"type": "https://example.org/test/1.0",
					"from": "did:example:alice",
					"body": {"message": "This is signed with EdDSA"}
				}`),
			},
			// ES256 signing
			{
				Name:        "sign_es256",
				Description: "Sign message with ES256 (P-256)",
				Category:    "signing",
				SenderDID:   "did:example:alice",
				SenderKeyID: "did:example:alice#key-p256-1",
				SigningAlg:  "ES256",
				IsSigned:    true,
				Plaintext: json.RawMessage(`{
					"id": "signed-message-2",
					"type": "https://example.org/test/1.0",
					"from": "did:example:alice",
					"body": {"message": "This is signed with ES256"}
				}`),
			},
		},
	}
}

// MessageTestVectors returns test vectors for message format validation.
func MessageTestVectors() *TestVectorSuite {
	return &TestVectorSuite{
		Name:        "message",
		Description: "DIDComm message format test vectors",
		Vectors: []*TestVector{
			// Basic message
			{
				Name:        "basic_message",
				Description: "Basic DIDComm plaintext message",
				Category:    "message",
				Plaintext: json.RawMessage(`{
					"id": "basic-1",
					"type": "https://example.org/protocols/1.0/basic",
					"body": {}
				}`),
			},
			// Message with all fields
			{
				Name:         "full_message",
				Description:  "DIDComm message with all optional fields",
				Category:     "message",
				SenderDID:    "did:example:alice",
				RecipientDID: "did:example:bob",
				Plaintext: json.RawMessage(`{
					"id": "full-1",
					"type": "https://example.org/protocols/1.0/full",
					"from": "did:example:alice",
					"to": ["did:example:bob"],
					"created_time": 1699900000,
					"body": {
						"field1": "value1",
						"field2": 42
					}
				}`),
			},
			// Message with attachment
			{
				Name:        "message_with_attachment",
				Description: "DIDComm message with base64 attachment",
				Category:    "message",
				Plaintext: json.RawMessage(`{
					"id": "attach-1",
					"type": "https://example.org/protocols/1.0/attach",
					"body": {},
					"attachments": [
						{
							"id": "attachment-1",
							"media_type": "application/json",
							"data": {
								"base64": "eyJoZWxsbyI6IndvcmxkIn0="
							}
						}
					]
				}`),
			},
			// Trust Ping message
			{
				Name:         "trust_ping",
				Description:  "Trust Ping protocol message",
				Category:     "message",
				SenderDID:    "did:example:alice",
				RecipientDID: "did:example:bob",
				Plaintext: json.RawMessage(`{
					"id": "ping-1",
					"type": "https://didcomm.org/trust-ping/2.0/ping",
					"from": "did:example:alice",
					"to": ["did:example:bob"],
					"body": {
						"response_requested": true
					}
				}`),
			},
			// OOB Invitation
			{
				Name:        "oob_invitation",
				Description: "Out-of-Band invitation message",
				Category:    "message",
				SenderDID:   "did:example:alice",
				Plaintext: json.RawMessage(`{
					"id": "invitation-1",
					"type": "https://didcomm.org/out-of-band/2.0/invitation",
					"from": "did:example:alice",
					"body": {
						"goal": "establish-connection",
						"goal_code": "connect",
						"accept": ["didcomm/v2"]
					}
				}`),
			},
		},
	}
}

// RoundTripTestVectors returns test vectors for encrypt/decrypt and sign/verify round trips.
func RoundTripTestVectors() *TestVectorSuite {
	return &TestVectorSuite{
		Name:        "roundtrip",
		Description: "Round-trip encryption and signing test vectors",
		Vectors: []*TestVector{
			// Sign then encrypt
			{
				Name:           "sign_then_encrypt",
				Description:    "Sign message then encrypt (non-repudiation)",
				Category:       "roundtrip",
				SenderDID:      "did:example:alice",
				SenderKeyID:    "did:example:alice#key-ed25519-1",
				RecipientDID:   "did:example:bob",
				RecipientKeyID: "did:example:bob#key-x25519-1",
				SigningAlg:     "EdDSA",
				Algorithm:      "ECDH-1PU+A256KW",
				Encryption:     "A256CBC-HS512",
				IsSigned:       true,
				IsAuthcrypt:    true,
				Plaintext: json.RawMessage(`{
					"id": "nonrepudiation-1",
					"type": "https://example.org/protocols/1.0/important",
					"from": "did:example:alice",
					"to": ["did:example:bob"],
					"body": {
						"content": "This message has non-repudiation"
					}
				}`),
			},
			// Multi-recipient encryption
			{
				Name:        "multi_recipient",
				Description: "Encrypt to multiple recipients",
				Category:    "roundtrip",
				SenderDID:   "did:example:alice",
				Algorithm:   "ECDH-ES+A256KW",
				Encryption:  "A256GCM",
				IsAnoncrypt: true,
				Plaintext: json.RawMessage(`{
					"id": "multi-1",
					"type": "https://example.org/protocols/1.0/broadcast",
					"from": "did:example:alice",
					"to": ["did:example:bob", "did:example:charlie"],
					"body": {
						"content": "Message to multiple recipients"
					}
				}`),
			},
		},
	}
}

// ErrorTestVectors returns test vectors that should produce errors.
func ErrorTestVectors() *TestVectorSuite {
	return &TestVectorSuite{
		Name:        "errors",
		Description: "Test vectors that should produce errors",
		Vectors: []*TestVector{
			// Missing required field
			{
				Name:           "missing_id",
				Description:    "Message missing required 'id' field",
				Category:       "error",
				ExpectError:    true,
				ExpectedErrMsg: "missing required field: id",
				Plaintext:      json.RawMessage(`{"type": "test"}`),
			},
			// Missing required field
			{
				Name:           "missing_type",
				Description:    "Message missing required 'type' field",
				Category:       "error",
				ExpectError:    true,
				ExpectedErrMsg: "missing required field: type",
				Plaintext:      json.RawMessage(`{"id": "test-1"}`),
			},
			// Invalid JSON
			{
				Name:           "invalid_json",
				Description:    "Malformed JSON message",
				Category:       "error",
				ExpectError:    true,
				ExpectedErrMsg: "invalid JSON",
				Plaintext:      json.RawMessage(`{not valid json`),
			},
		},
	}
}

// AllTestVectors returns all test vector suites.
func AllTestVectors() []*TestVectorSuite {
	return []*TestVectorSuite{
		EncryptionTestVectors(),
		SigningTestVectors(),
		MessageTestVectors(),
		RoundTripTestVectors(),
		ErrorTestVectors(),
	}
}

// GetTestVector finds a test vector by name across all suites.
func GetTestVector(name string) (*TestVector, error) {
	for _, suite := range AllTestVectors() {
		for _, v := range suite.Vectors {
			if v.Name == name {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("test vector not found: %s", name)
}

// GetTestVectorsByCategory returns all test vectors in a category.
func GetTestVectorsByCategory(category string) []*TestVector {
	var vectors []*TestVector
	for _, suite := range AllTestVectors() {
		for _, v := range suite.Vectors {
			if v.Category == category {
				vectors = append(vectors, v)
			}
		}
	}
	return vectors
}

// ValidateTestVector validates that a test vector is well-formed.
func ValidateTestVector(v *TestVector) error {
	if v.Name == "" {
		return fmt.Errorf("test vector missing name")
	}
	if v.Category == "" {
		return fmt.Errorf("test vector %s missing category", v.Name)
	}
	return nil
}
