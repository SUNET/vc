//go:build didcomm && vc20

package trustping

import (
	"fmt"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
)

const (
	// Protocol identifier
	ProtocolURI = "https://didcomm.org/trust-ping/2.0"

	// Message types
	TypePing         = ProtocolURI + "/ping"
	TypePingResponse = ProtocolURI + "/ping-response"
)

// Ping represents a trust ping message.
type Ping struct {
	*message.Message
}

// PingResponse represents a trust ping response message.
type PingResponse struct {
	*message.Message
}

// PingBody contains the body fields for a ping message.
type PingBody struct {
	// ResponseRequested indicates whether a response is expected.
	// If false, the receiver should not respond.
	ResponseRequested bool `json:"response_requested,omitempty"`

	// Comment is an optional human-readable message.
	Comment string `json:"comment,omitempty"`
}

// PingResponseBody contains the body fields for a ping response.
type PingResponseBody struct {
	// Comment is an optional human-readable message.
	Comment string `json:"comment,omitempty"`
}

// PingOption configures ping creation.
type PingOption func(*pingConfig)

type pingConfig struct {
	responseRequested bool
	comment           string
}

// WithResponseRequested sets whether a response is expected.
func WithResponseRequested(requested bool) PingOption {
	return func(c *pingConfig) {
		c.responseRequested = requested
	}
}

// WithComment adds a human-readable comment.
func WithComment(comment string) PingOption {
	return func(c *pingConfig) {
		c.comment = comment
	}
}

// NewPing creates a new trust ping message.
func NewPing(from, to string, opts ...PingOption) (*message.Message, error) {
	cfg := &pingConfig{
		responseRequested: true, // Default to expecting a response
	}
	for _, opt := range opts {
		opt(cfg)
	}

	body := PingBody{
		ResponseRequested: cfg.responseRequested,
		Comment:           cfg.comment,
	}

	msgOpts := []message.Option{
		message.WithType(TypePing),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set ping body: %w", err)
	}

	return msg, nil
}

// NewPingResponse creates a response to a ping message.
func NewPingResponse(ping *message.Message, comment string) (*message.Message, error) {
	if ping.Type != TypePing {
		return nil, fmt.Errorf("%w: expected %s, got %s", didcomm.ErrInvalidMessage, TypePing, ping.Type)
	}

	// Response goes back to the sender
	from := ""
	if len(ping.To) > 0 {
		from = ping.To[0]
	}

	to := ping.From

	msgOpts := []message.Option{
		message.WithType(TypePingResponse),
		message.WithThreadID(ping.ThreadID()),
	}

	if from != "" {
		msgOpts = append(msgOpts, message.WithFrom(from))
	}
	if to != "" {
		msgOpts = append(msgOpts, message.WithTo(to))
	}

	msg := message.New(msgOpts...)

	if comment != "" {
		body := PingResponseBody{Comment: comment}
		if err := msg.SetBody(body); err != nil {
			return nil, fmt.Errorf("failed to set response body: %w", err)
		}
	}

	return msg, nil
}

// IsPing checks if a message is a trust ping.
func IsPing(msg *message.Message) bool {
	return msg.Type == TypePing
}

// IsPingResponse checks if a message is a trust ping response.
func IsPingResponse(msg *message.Message) bool {
	return msg.Type == TypePingResponse
}

// ResponseRequested returns whether a ping expects a response.
func ResponseRequested(msg *message.Message) bool {
	if msg.Type != TypePing {
		return false
	}

	var body PingBody
	if err := msg.GetBody(&body); err != nil {
		// Default to true if body can't be parsed
		return true
	}

	return body.ResponseRequested
}

// HandlePing processes a ping message and returns a response if requested.
// Returns nil if no response is needed.
func HandlePing(ping *message.Message) (*message.Message, error) {
	if !IsPing(ping) {
		return nil, fmt.Errorf("%w: not a ping message", didcomm.ErrInvalidMessage)
	}

	if !ResponseRequested(ping) {
		return nil, nil
	}

	return NewPingResponse(ping, "")
}
