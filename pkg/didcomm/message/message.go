package message

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Message represents a DIDComm v2.1 plaintext message.
// Per DIDComm spec Section 3.
type Message struct {
	// ID is a unique identifier for the message. REQUIRED.
	// MUST be unique to the sender.
	ID string `json:"id"`

	// Type is the message type URI. REQUIRED.
	// Defines the protocol and message semantics.
	Type string `json:"type"`

	// From is the sender's DID. OPTIONAL for anonymous messages.
	// When present, the message can be authenticated.
	From string `json:"from,omitempty"`

	// To is the list of recipient DIDs. OPTIONAL but typically present.
	// Messages may omit To when the recipient is implicit.
	To []string `json:"to,omitempty"`

	// ThID is the thread identifier. OPTIONAL.
	// Groups related messages together.
	ThID string `json:"thid,omitempty"`

	// PThID is the parent thread identifier. OPTIONAL.
	// Links a thread to a parent thread.
	PThID string `json:"pthid,omitempty"`

	// CreatedTime is when the message was created. OPTIONAL.
	// Unix timestamp in seconds.
	CreatedTime *int64 `json:"created_time,omitempty"`

	// ExpiresTime is when the message expires. OPTIONAL.
	// Unix timestamp in seconds.
	ExpiresTime *int64 `json:"expires_time,omitempty"`

	// Body is the message-type-specific content. OPTIONAL.
	// Structure depends on the message type.
	Body any `json:"body,omitempty"`

	// Attachments is a list of attachments. OPTIONAL.
	Attachments []Attachment `json:"attachments,omitempty"`

	// FromPrior is a JWT for sender key rotation. OPTIONAL.
	// Proves continuity when the sender's DID or keys change.
	FromPrior string `json:"from_prior,omitempty"`

	// PleaseAck requests acknowledgment of this message. OPTIONAL.
	// Contains a list of message IDs that should trigger an ack.
	PleaseAck []string `json:"please_ack,omitempty"`

	// Ack acknowledges receipt of previous messages. OPTIONAL.
	// Contains message IDs being acknowledged.
	Ack []string `json:"ack,omitempty"`

	// CustomHeaders contains additional headers not in the spec.
	// These are serialized at the top level of the message JSON.
	CustomHeaders map[string]any `json:"-"`
}

// New creates a new Message with a generated UUID and applies the given options.
func New(opts ...Option) *Message {
	m := &Message{
		ID: uuid.New().String(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Option is a functional option for creating messages.
type Option func(*Message)

// WithID sets the message ID.
func WithID(id string) Option {
	return func(m *Message) {
		m.ID = id
	}
}

// WithType sets the message type URI.
func WithType(typ string) Option {
	return func(m *Message) {
		m.Type = typ
	}
}

// WithFrom sets the sender DID.
func WithFrom(from string) Option {
	return func(m *Message) {
		m.From = from
	}
}

// WithTo sets the recipient DIDs.
func WithTo(to ...string) Option {
	return func(m *Message) {
		m.To = to
	}
}

// WithThreadID sets the thread identifier.
func WithThreadID(thid string) Option {
	return func(m *Message) {
		m.ThID = thid
	}
}

// WithParentThreadID sets the parent thread identifier.
func WithParentThreadID(pthid string) Option {
	return func(m *Message) {
		m.PThID = pthid
	}
}

// WithBody sets the message body.
func WithBody(body any) Option {
	return func(m *Message) {
		m.Body = body
	}
}

// WithCreatedTime sets the creation timestamp.
func WithCreatedTime(t time.Time) Option {
	return func(m *Message) {
		ts := t.Unix()
		m.CreatedTime = &ts
	}
}

// WithExpiresTime sets the expiration timestamp.
func WithExpiresTime(t time.Time) Option {
	return func(m *Message) {
		ts := t.Unix()
		m.ExpiresTime = &ts
	}
}

// WithAttachments sets the message attachments.
func WithAttachments(attachments []Attachment) Option {
	return func(m *Message) {
		m.Attachments = attachments
	}
}

// WithFromPrior sets the from_prior JWT.
func WithFromPrior(jwt string) Option {
	return func(m *Message) {
		m.FromPrior = jwt
	}
}

// AddAttachment adds an attachment to the message.
func (m *Message) AddAttachment(a Attachment) {
	m.Attachments = append(m.Attachments, a)
}

// SetBody sets the message body from a struct.
func (m *Message) SetBody(body any) error {
	m.Body = body
	return nil
}

// GetBody unmarshals the message body into the given struct.
func (m *Message) GetBody(v any) error {
	if m.Body == nil {
		return nil
	}

	// If body is already the correct type, we need to marshal and unmarshal
	data, err := json.Marshal(m.Body)
	if err != nil {
		return fmt.Errorf("failed to marshal body: %w", err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return nil
}

// ThreadID returns the effective thread ID.
// If thid is set, returns it; otherwise returns the message id.
func (m *Message) ThreadID() string {
	if m.ThID != "" {
		return m.ThID
	}
	return m.ID
}

// IsExpired returns true if the message has expired.
func (m *Message) IsExpired() bool {
	if m.ExpiresTime == nil {
		return false
	}
	return time.Now().Unix() > *m.ExpiresTime
}

// Reply creates a new message that is a reply to this message.
// The thread ID is preserved (or set from the original message ID).
func (m *Message) Reply(typ string, body any) *Message {
	return New(
		WithType(typ),
		WithTo(m.From),
		WithThreadID(m.ThreadID()),
		WithBody(body),
	)
}

// Validate checks that the message meets DIDComm requirements.
func (m *Message) Validate() error {
	if m.ID == "" {
		return ErrMissingID
	}
	if m.Type == "" {
		return ErrMissingType
	}
	if m.IsExpired() {
		return ErrMessageExpired
	}
	for i, a := range m.Attachments {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("attachment %d: %w", i, err)
		}
	}
	return nil
}

// MarshalJSON implements json.Marshaler with custom header support.
func (m *Message) MarshalJSON() ([]byte, error) {
	// Create a map with all standard fields
	data := make(map[string]any)

	data["id"] = m.ID
	data["type"] = m.Type

	if m.From != "" {
		data["from"] = m.From
	}
	if len(m.To) > 0 {
		data["to"] = m.To
	}
	if m.ThID != "" {
		data["thid"] = m.ThID
	}
	if m.PThID != "" {
		data["pthid"] = m.PThID
	}
	if m.CreatedTime != nil {
		data["created_time"] = *m.CreatedTime
	}
	if m.ExpiresTime != nil {
		data["expires_time"] = *m.ExpiresTime
	}
	if m.Body != nil {
		data["body"] = m.Body
	}
	if len(m.Attachments) > 0 {
		data["attachments"] = m.Attachments
	}
	if m.FromPrior != "" {
		data["from_prior"] = m.FromPrior
	}
	if len(m.PleaseAck) > 0 {
		data["please_ack"] = m.PleaseAck
	}
	if len(m.Ack) > 0 {
		data["ack"] = m.Ack
	}

	// Add custom headers
	for k, v := range m.CustomHeaders {
		if _, exists := data[k]; !exists {
			data[k] = v
		}
	}

	return json.Marshal(data)
}

// UnmarshalJSON implements json.Unmarshaler with custom header support.
func (m *Message) UnmarshalJSON(data []byte) error {
	// First unmarshal known fields
	type messageAlias Message
	alias := &messageAlias{}
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	*m = Message(*alias)

	// Unmarshal to map to capture custom headers
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Known fields to exclude from custom headers
	knownFields := map[string]bool{
		"id": true, "type": true, "from": true, "to": true,
		"thid": true, "pthid": true, "created_time": true,
		"expires_time": true, "body": true, "attachments": true,
		"from_prior": true, "please_ack": true, "ack": true,
	}

	for k, v := range raw {
		if !knownFields[k] {
			if m.CustomHeaders == nil {
				m.CustomHeaders = make(map[string]any)
			}
			var val any
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			m.CustomHeaders[k] = val
		}
	}

	return nil
}

// Parse parses a JSON-encoded plaintext message.
func Parse(data []byte) (*Message, error) {
	m := &Message{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}
