//go:build didcomm && vc20

package message

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Attachment represents a DIDComm message attachment.
// Per DIDComm spec Section 3.4.
type Attachment struct {
	// ID is a unique identifier for the attachment within the message.
	// REQUIRED when attachments are referenced by other parts of the message.
	ID string `json:"id,omitempty"`

	// Description is a human-readable description. OPTIONAL.
	Description string `json:"description,omitempty"`

	// Filename is a hint about the filename. OPTIONAL.
	Filename string `json:"filename,omitempty"`

	// MediaType is the MIME type of the attachment content. OPTIONAL.
	MediaType string `json:"media_type,omitempty"`

	// Format describes the format of the attachment if not evident from media_type. OPTIONAL.
	Format string `json:"format,omitempty"`

	// LastModTime is the last modification time. OPTIONAL.
	// Unix timestamp in seconds.
	LastModTime *int64 `json:"lastmod_time,omitempty"`

	// ByteCount is the size in bytes. OPTIONAL.
	ByteCount *int64 `json:"byte_count,omitempty"`

	// Data contains the attachment data. REQUIRED.
	Data AttachmentData `json:"data"`
}

// AttachmentData represents the actual attachment content.
// Exactly one of JWS, Hash, Links, Base64, or JSON should be set.
type AttachmentData struct {
	// JWS is a JSON Web Signature wrapping the content.
	// Provides integrity and optional authentication.
	JWS json.RawMessage `json:"jws,omitempty"`

	// Hash is a multihash of the content for integrity checking.
	// Used when content is retrieved via Links.
	Hash string `json:"hash,omitempty"`

	// Links is a list of URIs where the content can be fetched.
	Links []string `json:"links,omitempty"`

	// Base64 is base64url-encoded content.
	Base64 string `json:"base64,omitempty"`

	// JSON is embedded JSON content.
	JSON any `json:"json,omitempty"`
}

// Validate checks that the attachment is well-formed.
func (a *Attachment) Validate() error {
	if err := a.Data.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAttachment, err)
	}
	return nil
}

// GetBytes returns the attachment content as bytes.
// Works for Base64 and JSON encoded content.
func (a *Attachment) GetBytes() ([]byte, error) {
	if a.Data.Base64 != "" {
		return base64.URLEncoding.DecodeString(a.Data.Base64)
	}
	if a.Data.JSON != nil {
		return json.Marshal(a.Data.JSON)
	}
	if len(a.Data.Links) > 0 {
		return nil, fmt.Errorf("attachment data must be fetched from links")
	}
	return nil, fmt.Errorf("no attachment data available")
}

// DecodeBase64 decodes base64-encoded attachment data.
// Returns an error if the attachment doesn't have base64 data.
func (a *Attachment) DecodeBase64() ([]byte, error) {
	if a.Data.Base64 == "" {
		return nil, fmt.Errorf("attachment has no base64 data")
	}
	// Try URL encoding first, then standard encoding
	data, err := base64.RawURLEncoding.DecodeString(a.Data.Base64)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(a.Data.Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64: %w", err)
		}
	}
	return data, nil
}

// GetJSON returns the attachment content as a JSON-decoded value.
// If the content is Base64-encoded JSON, it will be decoded.
func (a *Attachment) GetJSON(v any) error {
	if a.Data.JSON != nil {
		// Already JSON, marshal then unmarshal to target type
		data, err := json.Marshal(a.Data.JSON)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, v)
	}
	if a.Data.Base64 != "" {
		data, err := base64.URLEncoding.DecodeString(a.Data.Base64)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, v)
	}
	return fmt.Errorf("no JSON data available")
}

// Validate checks that exactly one data format is specified.
func (d *AttachmentData) Validate() error {
	count := 0
	if d.JWS != nil {
		count++
	}
	if d.Base64 != "" {
		count++
	}
	if d.JSON != nil {
		count++
	}
	if len(d.Links) > 0 {
		count++
	}

	if count == 0 {
		return fmt.Errorf("attachment data must specify jws, base64, json, or links")
	}
	// Note: DIDComm spec allows multiple formats, so we don't check count > 1

	return nil
}

// NewBase64Attachment creates an attachment with base64-encoded data.
func NewBase64Attachment(id string, mediaType string, data []byte) Attachment {
	return Attachment{
		ID:        id,
		MediaType: mediaType,
		Data: AttachmentData{
			Base64: base64.URLEncoding.EncodeToString(data),
		},
	}
}

// NewJSONAttachment creates an attachment with embedded JSON data.
func NewJSONAttachment(id string, data any) Attachment {
	return Attachment{
		ID:        id,
		MediaType: "application/json",
		Data: AttachmentData{
			JSON: data,
		},
	}
}

// NewLinksAttachment creates an attachment with external links.
func NewLinksAttachment(id string, mediaType string, links []string, hash string) Attachment {
	return Attachment{
		ID:        id,
		MediaType: mediaType,
		Data: AttachmentData{
			Links: links,
			Hash:  hash,
		},
	}
}
