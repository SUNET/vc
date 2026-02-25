//go:build didcomm && vc20

package oob

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
)

const (
	// Protocol identifier
	ProtocolURI = "https://didcomm.org/out-of-band/2.0"

	// Message types
	TypeInvitation = ProtocolURI + "/invitation"

	// URL parameter name
	OOBQueryParam = "_oob"
)

// Invitation represents an out-of-band invitation message.
type Invitation struct {
	*message.Message
}

// InvitationBody contains the body fields for an invitation.
type InvitationBody struct {
	// GoalCode is a machine-readable code describing the goal.
	GoalCode string `json:"goal_code,omitempty"`

	// Goal is a human-readable description of the goal.
	Goal string `json:"goal,omitempty"`

	// Accept is a list of media types the sender accepts.
	Accept []string `json:"accept,omitempty"`

	// Handshake protocols the sender supports.
	HandshakeProtocols []string `json:"handshake_protocols,omitempty"`
}

// InvitationOption configures invitation creation.
type InvitationOption func(*invitationConfig)

type invitationConfig struct {
	goalCode           string
	goal               string
	label              string
	accept             []string
	handshakeProtocols []string
	attachments        []message.Attachment
}

// WithGoalCode sets the machine-readable goal code.
func WithGoalCode(code string) InvitationOption {
	return func(c *invitationConfig) {
		c.goalCode = code
	}
}

// WithGoal sets the human-readable goal description.
func WithGoal(goal string) InvitationOption {
	return func(c *invitationConfig) {
		c.goal = goal
	}
}

// WithLabel sets a label for the invitation (used in from header).
func WithLabel(label string) InvitationOption {
	return func(c *invitationConfig) {
		c.label = label
	}
}

// WithAccept sets the accepted media types.
func WithAccept(mediaTypes ...string) InvitationOption {
	return func(c *invitationConfig) {
		c.accept = mediaTypes
	}
}

// WithHandshakeProtocols sets the supported handshake protocols.
func WithHandshakeProtocols(protocols ...string) InvitationOption {
	return func(c *invitationConfig) {
		c.handshakeProtocols = protocols
	}
}

// WithAttachments adds attachments to the invitation.
func WithAttachments(attachments ...message.Attachment) InvitationOption {
	return func(c *invitationConfig) {
		c.attachments = attachments
	}
}

// NewInvitation creates a new out-of-band invitation.
func NewInvitation(from string, opts ...InvitationOption) (*message.Message, error) {
	cfg := &invitationConfig{
		accept: []string{
			didcomm.MediaTypeEncrypted,
			didcomm.MediaTypeSigned,
			didcomm.MediaTypePlaintext,
		},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	body := InvitationBody{
		GoalCode:           cfg.goalCode,
		Goal:               cfg.goal,
		Accept:             cfg.accept,
		HandshakeProtocols: cfg.handshakeProtocols,
	}

	msgOpts := []message.Option{
		message.WithType(TypeInvitation),
		message.WithFrom(from),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set invitation body: %w", err)
	}

	if len(cfg.attachments) > 0 {
		msg.Attachments = cfg.attachments
	}

	return msg, nil
}

// IsInvitation checks if a message is an out-of-band invitation.
func IsInvitation(msg *message.Message) bool {
	return msg.Type == TypeInvitation
}

// EncodeAsURL encodes an invitation as a URL with an _oob query parameter.
// The baseURL should be the endpoint where invitations are handled.
func EncodeAsURL(inv *message.Message, baseURL string) (string, error) {
	if !IsInvitation(inv) {
		return "", fmt.Errorf("%w: not an invitation message", didcomm.ErrInvalidMessage)
	}

	// Serialize to JSON
	jsonBytes, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	// Base64url encode
	encoded := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// Build URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set(OOBQueryParam, encoded)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// EncodeAsJSON encodes an invitation as a JSON string.
func EncodeAsJSON(inv *message.Message) (string, error) {
	if !IsInvitation(inv) {
		return "", fmt.Errorf("%w: not an invitation message", didcomm.ErrInvalidMessage)
	}

	jsonBytes, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	return string(jsonBytes), nil
}

// DecodeFromURL decodes an invitation from a URL containing an _oob parameter.
func DecodeFromURL(invURL string) (*message.Message, error) {
	u, err := url.Parse(invURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	encoded := u.Query().Get(OOBQueryParam)
	if encoded == "" {
		return nil, fmt.Errorf("%w: missing %s parameter", didcomm.ErrInvalidMessage, OOBQueryParam)
	}

	return DecodeFromBase64(encoded)
}

// DecodeFromBase64 decodes an invitation from a base64url-encoded string.
func DecodeFromBase64(encoded string) (*message.Message, error) {
	// Handle both standard and URL-safe base64
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.TrimRight(encoded, "=")

	jsonBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return DecodeFromJSON(jsonBytes)
}

// DecodeFromJSON decodes an invitation from JSON bytes.
func DecodeFromJSON(jsonBytes []byte) (*message.Message, error) {
	msg, err := message.Parse(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse invitation: %w", err)
	}

	if !IsInvitation(msg) {
		return nil, fmt.Errorf("%w: expected %s, got %s", didcomm.ErrInvalidMessage, TypeInvitation, msg.Type)
	}

	return msg, nil
}

// GetInvitationBody extracts the body from an invitation message.
func GetInvitationBody(inv *message.Message) (*InvitationBody, error) {
	if !IsInvitation(inv) {
		return nil, fmt.Errorf("%w: not an invitation message", didcomm.ErrInvalidMessage)
	}

	var body InvitationBody
	if err := inv.GetBody(&body); err != nil {
		return nil, err
	}

	return &body, nil
}
