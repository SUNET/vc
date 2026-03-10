package didcomm_interop

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"vc/pkg/didcomm/message"
	"vc/test/didcomm_interop/vectors"
)

// TestMessageParsing tests parsing of DIDComm messages from JSON.
func TestMessageParsing(t *testing.T) {
	suite := vectors.MessageTestVectors()

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			msg, err := message.Parse(vec.Plaintext)
			if vec.ExpectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to parse message: %v", err)
			}

			// Validate required fields
			if msg.ID == "" {
				t.Error("message ID should not be empty")
			}
			if msg.Type == "" {
				t.Error("message type should not be empty")
			}

			t.Logf("✓ Parsed message: ID=%s Type=%s", msg.ID, msg.Type)
		})
	}
}

// TestMessageSerialization tests serialization of DIDComm messages to JSON.
func TestMessageSerialization(t *testing.T) {
	testCases := []struct {
		name    string
		message *message.Message
	}{
		{
			name: "basic_message",
			message: message.New(
				message.WithID("test-1"),
				message.WithType("https://example.org/test/1.0"),
			),
		},
		{
			name: "message_with_from",
			message: message.New(
				message.WithID("test-2"),
				message.WithType("https://example.org/test/1.0"),
				message.WithFrom("did:example:alice"),
			),
		},
		{
			name: "message_with_to",
			message: message.New(
				message.WithID("test-3"),
				message.WithType("https://example.org/test/1.0"),
				message.WithTo("did:example:bob", "did:example:charlie"),
			),
		},
		{
			name: "message_with_body",
			message: message.New(
				message.WithID("test-4"),
				message.WithType("https://example.org/test/1.0"),
				message.WithBody(map[string]interface{}{
					"content": "Hello, World!",
					"count":   42,
				}),
			),
		},
		{
			name: "full_message",
			message: func() *message.Message {
				m := message.New(
					message.WithID("test-5"),
					message.WithType("https://example.org/test/1.0"),
					message.WithFrom("did:example:alice"),
					message.WithTo("did:example:bob"),
					message.WithBody(map[string]interface{}{
						"nested": map[string]interface{}{
							"field": "value",
						},
					}),
				)
				ts := int64(1699900000)
				m.CreatedTime = &ts
				// No expires_time to avoid validation failures
				return m
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize to JSON
			data, err := json.Marshal(tc.message)
			if err != nil {
				t.Fatalf("failed to serialize: %v", err)
			}

			t.Logf("Serialized: %s", string(data))

			// Parse back
			parsed, err := message.Parse(data)
			if err != nil {
				t.Fatalf("failed to parse serialized message: %v", err)
			}

			// Verify round-trip
			if parsed.ID != tc.message.ID {
				t.Errorf("ID mismatch: got %q, want %q", parsed.ID, tc.message.ID)
			}
			if parsed.Type != tc.message.Type {
				t.Errorf("Type mismatch: got %q, want %q", parsed.Type, tc.message.Type)
			}
			if parsed.From != tc.message.From {
				t.Errorf("From mismatch: got %q, want %q", parsed.From, tc.message.From)
			}

			t.Logf("✓ Round-trip successful for %s", tc.name)
		})
	}
}

// TestMessageValidation tests message validation rules.
func TestMessageValidation(t *testing.T) {
	testCases := []struct {
		name        string
		message     *message.Message
		expectError bool
		errorField  string
	}{
		{
			name: "valid_minimal",
			message: message.New(
				message.WithID("id-1"),
				message.WithType("type-1"),
			),
			expectError: false,
		},
		{
			name: "valid_full",
			message: message.New(
				message.WithID("id-2"),
				message.WithType("type-2"),
				message.WithFrom("did:example:alice"),
				message.WithTo("did:example:bob"),
			),
			expectError: false,
		},
		{
			name: "invalid_empty_id",
			message: message.New(
				message.WithID(""),
				message.WithType("type-3"),
			),
			expectError: true,
			errorField:  "id",
		},
		{
			name: "invalid_empty_type",
			message: message.New(
				message.WithID("id-4"),
				message.WithType(""),
			),
			expectError: true,
			errorField:  "type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.message.Validate()
			if tc.expectError {
				if err == nil {
					t.Errorf("expected validation error for field %s", tc.errorField)
				} else {
					t.Logf("✓ Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected validation error: %v", err)
				} else {
					t.Logf("✓ Validation passed for %s", tc.name)
				}
			}
		})
	}
}

// TestMessageAttachments tests attachment handling.
func TestMessageAttachments(t *testing.T) {
	t.Run("base64_attachment", func(t *testing.T) {
		m := message.New(
			message.WithID("attach-1"),
			message.WithType("https://example.org/test/1.0"),
		)

		// Add base64 attachment
		attachment := message.Attachment{
			ID:        "attachment-1",
			MediaType: "application/json",
			Data: message.AttachmentData{
				Base64: "eyJoZWxsbyI6IndvcmxkIn0=", // {"hello":"world"}
			},
		}
		m.Attachments = []message.Attachment{attachment}

		// Serialize and parse back
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(parsed.Attachments) != 1 {
			t.Fatalf("expected 1 attachment, got %d", len(parsed.Attachments))
		}

		att := parsed.Attachments[0]
		if att.ID != "attachment-1" {
			t.Errorf("attachment ID mismatch: got %q", att.ID)
		}
		if att.MediaType != "application/json" {
			t.Errorf("media type mismatch: got %q", att.MediaType)
		}

		// Decode the attachment data using standard base64
		if att.Data.Base64 == "" {
			t.Fatal("expected base64 data in attachment")
		}

		decoded, err := base64.StdEncoding.DecodeString(att.Data.Base64)
		if err != nil {
			t.Fatalf("failed to decode attachment: %v", err)
		}

		var content map[string]string
		if err := json.Unmarshal(decoded, &content); err != nil {
			t.Fatalf("failed to unmarshal decoded content: %v", err)
		}

		if content["hello"] != "world" {
			t.Errorf("decoded content mismatch: got %v", content)
		}

		t.Log("✓ Base64 attachment round-trip successful")
	})

	t.Run("json_attachment", func(t *testing.T) {
		m := message.New(
			message.WithID("attach-2"),
			message.WithType("https://example.org/test/1.0"),
		)

		// Add JSON attachment
		attachment := message.Attachment{
			ID:        "attachment-2",
			MediaType: "application/json",
			Data: message.AttachmentData{
				JSON: json.RawMessage(`{"nested":{"data":"value"}}`),
			},
		}
		m.Attachments = []message.Attachment{attachment}

		// Serialize and parse back
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(parsed.Attachments) != 1 {
			t.Fatalf("expected 1 attachment, got %d", len(parsed.Attachments))
		}

		att := parsed.Attachments[0]
		if att.Data.JSON == nil {
			t.Fatal("expected JSON attachment data")
		}

		// Get the JSON data
		jsonData, err := json.Marshal(att.Data.JSON)
		if err != nil {
			t.Fatalf("failed to marshal JSON attachment: %v", err)
		}

		var content map[string]interface{}
		if err := json.Unmarshal(jsonData, &content); err != nil {
			t.Fatalf("failed to unmarshal JSON attachment: %v", err)
		}

		nested, ok := content["nested"].(map[string]interface{})
		if !ok {
			t.Fatal("expected nested object")
		}
		if nested["data"] != "value" {
			t.Errorf("nested data mismatch: got %v", nested["data"])
		}

		t.Log("✓ JSON attachment round-trip successful")
	})

	t.Run("link_attachment", func(t *testing.T) {
		m := message.New(
			message.WithID("attach-3"),
			message.WithType("https://example.org/test/1.0"),
		)

		// Add link attachment
		hash := "abc123def456"
		attachment := message.Attachment{
			ID:        "attachment-3",
			MediaType: "application/pdf",
			Data: message.AttachmentData{
				Links: []string{"https://example.com/document.pdf"},
				Hash:  hash,
			},
		}
		m.Attachments = []message.Attachment{attachment}

		// Serialize and parse back
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if len(parsed.Attachments) != 1 {
			t.Fatalf("expected 1 attachment, got %d", len(parsed.Attachments))
		}

		att := parsed.Attachments[0]
		if len(att.Data.Links) != 1 {
			t.Fatalf("expected 1 link, got %d", len(att.Data.Links))
		}
		if att.Data.Links[0] != "https://example.com/document.pdf" {
			t.Errorf("link mismatch: got %q", att.Data.Links[0])
		}
		if att.Data.Hash != hash {
			t.Errorf("hash mismatch: got %q, want %q", att.Data.Hash, hash)
		}

		t.Log("✓ Link attachment round-trip successful")
	})
}

// TestMessageBodyGetSet tests body get/set operations.
func TestMessageBodyGetSet(t *testing.T) {
	t.Run("set_and_get_body", func(t *testing.T) {
		m := message.New(
			message.WithID("body-1"),
			message.WithType("https://example.org/test/1.0"),
		)

		// Set body
		body := map[string]interface{}{
			"string_field": "hello",
			"number_field": 42,
			"bool_field":   true,
			"nested": map[string]interface{}{
				"inner": "value",
			},
		}
		m.SetBody(body)

		// Get body
		var retrieved map[string]interface{}
		if err := m.GetBody(&retrieved); err != nil {
			t.Fatalf("failed to get body: %v", err)
		}

		if retrieved["string_field"] != "hello" {
			t.Errorf("string_field mismatch: got %v", retrieved["string_field"])
		}
		if retrieved["number_field"].(float64) != 42 {
			t.Errorf("number_field mismatch: got %v", retrieved["number_field"])
		}
		if retrieved["bool_field"] != true {
			t.Errorf("bool_field mismatch: got %v", retrieved["bool_field"])
		}

		t.Log("✓ Body get/set successful")
	})

	t.Run("typed_body", func(t *testing.T) {
		type CustomBody struct {
			ResponseRequested bool   `json:"response_requested"`
			Comment           string `json:"comment,omitempty"`
		}

		m := message.New(
			message.WithID("typed-1"),
			message.WithType("https://didcomm.org/trust-ping/2.0/ping"),
		)
		m.SetBody(CustomBody{
			ResponseRequested: true,
			Comment:           "ping!",
		})

		var body CustomBody
		if err := m.GetBody(&body); err != nil {
			t.Fatalf("failed to get typed body: %v", err)
		}

		if !body.ResponseRequested {
			t.Error("ResponseRequested should be true")
		}
		if body.Comment != "ping!" {
			t.Errorf("Comment mismatch: got %q", body.Comment)
		}

		t.Log("✓ Typed body get/set successful")
	})
}

// TestMessageErrorVectors tests messages that should fail parsing.
func TestMessageErrorVectors(t *testing.T) {
	suite := vectors.ErrorTestVectors()

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			_, err := message.Parse(vec.Plaintext)
			if err == nil {
				t.Errorf("expected error for %s", vec.Name)
			} else {
				t.Logf("✓ Got expected error: %v", err)
			}
		})
	}
}

// TestMessageThreading tests message threading (thid, pthid).
func TestMessageThreading(t *testing.T) {
	t.Run("explicit_thid", func(t *testing.T) {
		m := message.New(
			message.WithID("msg-1"),
			message.WithType("https://example.org/test/1.0"),
			message.WithThreadID("thread-123"),
		)

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if parsed.ThID != "thread-123" {
			t.Errorf("thid mismatch: got %q", parsed.ThID)
		}
		t.Log("✓ Explicit thid preserved")
	})

	t.Run("parent_thread", func(t *testing.T) {
		m := message.New(
			message.WithID("msg-2"),
			message.WithType("https://example.org/test/1.0"),
			message.WithThreadID("child-thread"),
			message.WithParentThreadID("parent-thread"),
		)

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if parsed.ThID != "child-thread" {
			t.Errorf("thid mismatch: got %q", parsed.ThID)
		}
		if parsed.PThID != "parent-thread" {
			t.Errorf("pthid mismatch: got %q", parsed.PThID)
		}
		t.Log("✓ Parent thread preserved")
	})

	t.Run("implicit_thid", func(t *testing.T) {
		// When thid is not set, it should default to the message ID
		m := message.New(
			message.WithID("msg-3"),
			message.WithType("https://example.org/test/1.0"),
		)

		threadID := m.ThreadID()
		if threadID != "msg-3" {
			t.Errorf("implicit thid should be message ID: got %q", threadID)
		}
		t.Log("✓ Implicit thid is message ID")
	})
}

// TestMessageAcknowledgment tests message routing with ack and please_ack.
func TestMessageAcknowledgment(t *testing.T) {
	t.Run("please_ack", func(t *testing.T) {
		m := message.New(
			message.WithID("ack-1"),
			message.WithType("https://example.org/test/1.0"),
		)
		m.PleaseAck = []string{"ack-1"}

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if len(parsed.PleaseAck) != 1 || parsed.PleaseAck[0] != "ack-1" {
			t.Errorf("please_ack mismatch: got %v", parsed.PleaseAck)
		}
		t.Log("✓ please_ack preserved")
	})

	t.Run("ack", func(t *testing.T) {
		m := message.New(
			message.WithID("ack-2"),
			message.WithType("https://example.org/test/1.0"),
		)
		m.Ack = []string{"previous-msg-1", "previous-msg-2"}

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := message.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if len(parsed.Ack) != 2 {
			t.Errorf("ack mismatch: got %v", parsed.Ack)
		}
		t.Log("✓ ack preserved")
	})
}
