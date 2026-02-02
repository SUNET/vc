//go:build didcomm && vc20

package didcomm

import (
	"context"
	"testing"

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
