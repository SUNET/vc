package message

import (
	"encoding/json"
	"testing"
)

func TestAttachment_Validate(t *testing.T) {
	tests := []struct {
		name    string
		attach  Attachment
		wantErr bool
	}{
		{
			name: "valid base64 attachment",
			attach: Attachment{
				ID:        "test-1",
				MediaType: "application/pdf",
				Data:      AttachmentData{Base64: "SGVsbG8gV29ybGQ"},
			},
			wantErr: false,
		},
		{
			name: "valid json attachment",
			attach: Attachment{
				ID: "test-2",
				Data: AttachmentData{
					JSON: map[string]any{"key": "value"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid links attachment",
			attach: Attachment{
				ID: "test-3",
				Data: AttachmentData{
					Links: []string{"https://example.com/file.pdf"},
					Hash:  "sha256-abc123",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty data",
			attach:  Attachment{ID: "test-4"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attach.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAttachment_GetBytes(t *testing.T) {
	t.Run("base64 content", func(t *testing.T) {
		attach := NewBase64Attachment("test", "text/plain", []byte("Hello World"))

		data, err := attach.GetBytes()
		if err != nil {
			t.Fatalf("GetBytes() error = %v", err)
		}

		if string(data) != "Hello World" {
			t.Errorf("GetBytes() = %s, want Hello World", string(data))
		}
	})

	t.Run("json content", func(t *testing.T) {
		attach := NewJSONAttachment("test", map[string]any{"key": "value"})

		data, err := attach.GetBytes()
		if err != nil {
			t.Fatalf("GetBytes() error = %v", err)
		}

		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if result["key"] != "value" {
			t.Errorf("expected key=value, got %v", result)
		}
	})

	t.Run("links only", func(t *testing.T) {
		attach := NewLinksAttachment("test", "application/pdf", []string{"https://example.com/file.pdf"}, "")

		_, err := attach.GetBytes()
		if err == nil {
			t.Error("expected error for links-only attachment")
		}
	})
}

func TestAttachment_GetJSON(t *testing.T) {
	t.Run("embedded json", func(t *testing.T) {
		attach := NewJSONAttachment("test", map[string]any{
			"name":  "Alice",
			"count": float64(42),
		})

		var result struct {
			Name  string  `json:"name"`
			Count float64 `json:"count"`
		}
		if err := attach.GetJSON(&result); err != nil {
			t.Fatalf("GetJSON() error = %v", err)
		}

		if result.Name != "Alice" || result.Count != 42 {
			t.Errorf("GetJSON() = %+v, want Alice/42", result)
		}
	})
}

func TestAttachment_JSON(t *testing.T) {
	attach := Attachment{
		ID:          "doc-1",
		Description: "A test document",
		MediaType:   "application/json",
		Filename:    "test.json",
		Data: AttachmentData{
			JSON: map[string]any{"test": true},
		},
	}

	data, err := json.Marshal(attach)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var parsed Attachment
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if parsed.ID != attach.ID {
		t.Errorf("ID = %v, want %v", parsed.ID, attach.ID)
	}
	if parsed.Description != attach.Description {
		t.Errorf("Description = %v, want %v", parsed.Description, attach.Description)
	}
	if parsed.MediaType != attach.MediaType {
		t.Errorf("MediaType = %v, want %v", parsed.MediaType, attach.MediaType)
	}
}

func TestNewBase64Attachment(t *testing.T) {
	attach := NewBase64Attachment("test-id", "application/pdf", []byte("PDF content"))

	if attach.ID != "test-id" {
		t.Errorf("ID = %v, want test-id", attach.ID)
	}
	if attach.MediaType != "application/pdf" {
		t.Errorf("MediaType = %v, want application/pdf", attach.MediaType)
	}
	if attach.Data.Base64 == "" {
		t.Error("expected Base64 to be set")
	}
}

func TestNewJSONAttachment(t *testing.T) {
	attach := NewJSONAttachment("test-id", map[string]string{"key": "value"})

	if attach.ID != "test-id" {
		t.Errorf("ID = %v, want test-id", attach.ID)
	}
	if attach.MediaType != "application/json" {
		t.Errorf("MediaType = %v, want application/json", attach.MediaType)
	}
	if attach.Data.JSON == nil {
		t.Error("expected JSON to be set")
	}
}

func TestNewLinksAttachment(t *testing.T) {
	links := []string{"https://example.com/file1.pdf", "https://example.com/file2.pdf"}
	attach := NewLinksAttachment("test-id", "application/pdf", links, "sha256-abc123")

	if attach.ID != "test-id" {
		t.Errorf("ID = %v, want test-id", attach.ID)
	}
	if len(attach.Data.Links) != 2 {
		t.Errorf("Links count = %d, want 2", len(attach.Data.Links))
	}
	if attach.Data.Hash != "sha256-abc123" {
		t.Errorf("Hash = %v, want sha256-abc123", attach.Data.Hash)
	}
}

func TestAttachment_DecodeBase64(t *testing.T) {
	attach := NewBase64Attachment("test", "text/plain", []byte("hello"))
	data, err := attach.DecodeBase64()
	if err != nil {
		t.Fatalf("DecodeBase64() error = %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected hello, got %s", string(data))
	}
}

func TestAttachment_DecodeBase64_Empty(t *testing.T) {
	attach := &Attachment{Data: AttachmentData{}}
	_, err := attach.DecodeBase64()
	if err == nil {
		t.Error("expected error for empty base64")
	}
}

func TestAttachment_GetJSON_FromBase64(t *testing.T) {
	jsonData := []byte(`{"name":"Bob"}`)
	attach := NewBase64Attachment("test", "application/json", jsonData)

	var result struct {
		Name string `json:"name"`
	}
	if err := attach.GetJSON(&result); err != nil {
		t.Fatalf("GetJSON() error = %v", err)
	}
	if result.Name != "Bob" {
		t.Errorf("expected Bob, got %s", result.Name)
	}
}

func TestAttachment_GetBytes_InvalidBase64(t *testing.T) {
	attach := &Attachment{Data: AttachmentData{Base64: "not-valid-base64!!!"}}
	_, err := attach.GetBytes()
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}
