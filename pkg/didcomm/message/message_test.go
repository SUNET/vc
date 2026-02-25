//go:build didcomm && vc20

package message

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	msg := New(
		WithType("https://example.com/protocols/1.0/test"),
		WithFrom("did:example:alice"),
		WithTo("did:example:bob"),
		WithBody(map[string]any{"hello": "world"}),
	)

	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Type != "https://example.com/protocols/1.0/test" {
		t.Errorf("expected type to be set, got %s", msg.Type)
	}
	if msg.From != "did:example:alice" {
		t.Errorf("expected from to be alice, got %s", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0] != "did:example:bob" {
		t.Errorf("expected to to be [bob], got %v", msg.To)
	}
}

func TestMessage_Validate(t *testing.T) {
	tests := []struct {
		name    string
		msg     *Message
		wantErr error
	}{
		{
			name: "valid message",
			msg: &Message{
				ID:   "123",
				Type: "https://example.com/test",
			},
			wantErr: nil,
		},
		{
			name: "missing id",
			msg: &Message{
				Type: "https://example.com/test",
			},
			wantErr: ErrMissingID,
		},
		{
			name: "missing type",
			msg: &Message{
				ID: "123",
			},
			wantErr: ErrMissingType,
		},
		{
			name: "expired message",
			msg: func() *Message {
				expired := time.Now().Add(-time.Hour).Unix()
				return &Message{
					ID:          "123",
					Type:        "https://example.com/test",
					ExpiresTime: &expired,
				}
			}(),
			wantErr: ErrMessageExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMessage_ThreadID(t *testing.T) {
	t.Run("with thid", func(t *testing.T) {
		msg := &Message{ID: "msg-1", ThID: "thread-1"}
		if got := msg.ThreadID(); got != "thread-1" {
			t.Errorf("ThreadID() = %v, want thread-1", got)
		}
	})

	t.Run("without thid", func(t *testing.T) {
		msg := &Message{ID: "msg-1"}
		if got := msg.ThreadID(); got != "msg-1" {
			t.Errorf("ThreadID() = %v, want msg-1", got)
		}
	})
}

func TestMessage_Reply(t *testing.T) {
	original := &Message{
		ID:   "original-msg",
		Type: "https://example.com/protocols/1.0/request",
		From: "did:example:alice",
		To:   []string{"did:example:bob"},
	}

	reply := original.Reply("https://example.com/protocols/1.0/response", map[string]any{"result": "ok"})

	if reply.ThID != "original-msg" {
		t.Errorf("expected thid to be original message id, got %s", reply.ThID)
	}
	if len(reply.To) != 1 || reply.To[0] != "did:example:alice" {
		t.Errorf("expected reply to be sent to alice, got %v", reply.To)
	}
	if reply.Type != "https://example.com/protocols/1.0/response" {
		t.Errorf("expected reply type to be response, got %s", reply.Type)
	}
}

func TestMessage_JSON(t *testing.T) {
	msg := New(
		WithID("test-123"),
		WithType("https://example.com/protocols/1.0/test"),
		WithFrom("did:example:alice"),
		WithTo("did:example:bob", "did:example:carol"),
		WithThreadID("thread-456"),
		WithBody(map[string]any{"message": "hello"}),
	)

	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var parsed Message
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if parsed.ID != msg.ID {
		t.Errorf("ID = %v, want %v", parsed.ID, msg.ID)
	}
	if parsed.Type != msg.Type {
		t.Errorf("Type = %v, want %v", parsed.Type, msg.Type)
	}
	if parsed.From != msg.From {
		t.Errorf("From = %v, want %v", parsed.From, msg.From)
	}
	if len(parsed.To) != len(msg.To) {
		t.Errorf("To = %v, want %v", parsed.To, msg.To)
	}
	if parsed.ThID != msg.ThID {
		t.Errorf("ThID = %v, want %v", parsed.ThID, msg.ThID)
	}
}

func TestMessage_CustomHeaders(t *testing.T) {
	jsonData := `{
		"id": "test-123",
		"type": "https://example.com/test",
		"custom_field": "custom_value",
		"another_custom": 42
	}`

	msg, err := Parse([]byte(jsonData))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if msg.CustomHeaders == nil {
		t.Fatal("expected custom headers to be populated")
	}
	if msg.CustomHeaders["custom_field"] != "custom_value" {
		t.Errorf("custom_field = %v, want custom_value", msg.CustomHeaders["custom_field"])
	}
	if msg.CustomHeaders["another_custom"] != float64(42) {
		t.Errorf("another_custom = %v, want 42", msg.CustomHeaders["another_custom"])
	}

	// Marshal back and verify custom headers are preserved
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if raw["custom_field"] != "custom_value" {
		t.Errorf("marshaled custom_field = %v, want custom_value", raw["custom_field"])
	}
}

func TestParse(t *testing.T) {
	t.Run("valid message", func(t *testing.T) {
		jsonData := `{
			"id": "123",
			"type": "https://example.com/test",
			"from": "did:example:alice",
			"to": ["did:example:bob"],
			"body": {"hello": "world"}
		}`

		msg, err := Parse([]byte(jsonData))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if msg.ID != "123" {
			t.Errorf("ID = %v, want 123", msg.ID)
		}
		if msg.Type != "https://example.com/test" {
			t.Errorf("Type = %v, want https://example.com/test", msg.Type)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := Parse([]byte("not json"))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		jsonData := `{"type": "https://example.com/test"}`
		_, err := Parse([]byte(jsonData))
		if err != ErrMissingID {
			t.Errorf("Parse() error = %v, want ErrMissingID", err)
		}
	})
}

func TestMessage_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		future := time.Now().Add(time.Hour).Unix()
		msg := &Message{ExpiresTime: &future}
		if msg.IsExpired() {
			t.Error("expected not expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		past := time.Now().Add(-time.Hour).Unix()
		msg := &Message{ExpiresTime: &past}
		if !msg.IsExpired() {
			t.Error("expected expired")
		}
	})

	t.Run("no expiry", func(t *testing.T) {
		msg := &Message{}
		if msg.IsExpired() {
			t.Error("expected not expired when no expiry set")
		}
	})
}
