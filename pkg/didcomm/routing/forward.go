package routing

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

// ForwardMessageType is the DIDComm message type for forward messages.
// Per DIDComm v2.1 spec Section 9.3.
const ForwardMessageType = "https://didcomm.org/routing/2.0/forward"

// Forward represents a DIDComm forward message used for routing.
// The forward message wraps an encrypted message and specifies the next hop.
type Forward struct {
	// ID is the unique message identifier.
	ID string `json:"id"`

	// Type is always ForwardMessageType.
	Type string `json:"type"`

	// To contains the DID of the mediator receiving this forward.
	To []string `json:"to,omitempty"`

	// Body contains the forward-specific fields.
	Body ForwardBody `json:"body"`

	// Attachments contains the wrapped message as an attachment.
	Attachments []message.Attachment `json:"attachments,omitempty"`
}

// ForwardBody contains the body of a forward message.
type ForwardBody struct {
	// Next is the DID or DID URL of the next recipient.
	// This is the entity that should receive the wrapped message.
	Next string `json:"next"`
}

// NewForward creates a new forward message.
//
// Parameters:
//   - mediatorDID: The DID of the mediator that will process this forward
//   - nextDID: The DID of the next recipient (may be final recipient or another mediator)
//   - wrappedMessage: The encrypted message to forward (as bytes)
func NewForward(mediatorDID, nextDID string, wrappedMessage []byte) *Forward {
	return &Forward{
		ID:   uuid.New().String(),
		Type: ForwardMessageType,
		To:   []string{mediatorDID},
		Body: ForwardBody{
			Next: nextDID,
		},
		Attachments: []message.Attachment{
			{
				ID:        uuid.New().String(),
				MediaType: "application/didcomm-encrypted+json",
				Data: message.AttachmentData{
					JSON: json.RawMessage(wrappedMessage),
				},
			},
		},
	}
}

// NewForwardWithID creates a new forward message with a specific ID.
func NewForwardWithID(id, mediatorDID, nextDID string, wrappedMessage []byte) *Forward {
	f := NewForward(mediatorDID, nextDID, wrappedMessage)
	f.ID = id
	return f
}

// GetWrappedMessage extracts the wrapped message from the forward's attachments.
func (f *Forward) GetWrappedMessage() ([]byte, error) {
	if len(f.Attachments) == 0 {
		return nil, fmt.Errorf("%w: no attachments", ErrInvalidForward)
	}

	att := f.Attachments[0]

	// Check for JSON data (inline encrypted message)
	if att.Data.JSON != nil {
		// JSON field is 'any', need to marshal it back to bytes
		return json.Marshal(att.Data.JSON)
	}

	// Check for base64 encoded data
	if att.Data.Base64 != "" {
		return att.DecodeBase64()
	}

	return nil, fmt.Errorf("%w: attachment has no data", ErrInvalidForward)
}

// ToMessage converts the Forward to a generic DIDComm message.
func (f *Forward) ToMessage() *message.Message {
	bodyMap := map[string]any{
		"next": f.Body.Next,
	}

	msg := message.New(
		message.WithID(f.ID),
		message.WithType(f.Type),
		message.WithBody(bodyMap),
	)

	if len(f.To) > 0 {
		msg.To = f.To
	}

	msg.Attachments = f.Attachments

	return msg
}

// ParseForward parses a DIDComm message as a forward message.
func ParseForward(msg *message.Message) (*Forward, error) {
	if msg.Type != ForwardMessageType {
		return nil, fmt.Errorf("%w: unexpected type %s", ErrInvalidForward, msg.Type)
	}

	// Extract 'next' from body
	body, ok := msg.Body.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: body is not a map", ErrInvalidForward)
	}

	next, ok := body["next"].(string)
	if !ok || next == "" {
		return nil, ErrMissingNext
	}

	return &Forward{
		ID:   msg.ID,
		Type: msg.Type,
		To:   msg.To,
		Body: ForwardBody{
			Next: next,
		},
		Attachments: msg.Attachments,
	}, nil
}

// ParseForwardFromJSON parses JSON bytes as a forward message.
func ParseForwardFromJSON(data []byte) (*Forward, error) {
	msg, err := message.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidForward, err)
	}

	return ParseForward(msg)
}

// Encrypter is an interface for encrypting messages for routing.
type Encrypter interface {
	// Encrypt encrypts a plaintext message for the given recipient keys.
	Encrypt(ctx context.Context, plaintext []byte, recipientDIDs []string) ([]byte, error)
}

// Decrypter is an interface for decrypting messages during routing.
type Decrypter interface {
	// Decrypt decrypts an encrypted message.
	Decrypt(ctx context.Context, encrypted []byte) ([]byte, error)
}

// WrapInForward wraps an encrypted message in a forward envelope.
// The resulting forward message should be encrypted for the mediator.
func WrapInForward(mediatorDID, nextDID string, encryptedMessage []byte) *Forward {
	return NewForward(mediatorDID, nextDID, encryptedMessage)
}

// UnwrapForward decrypts and unwraps a forward message.
// Returns the inner message, the next hop DID, and any error.
func UnwrapForward(ctx context.Context, encrypted []byte, decrypter Decrypter) (innerMessage []byte, nextHop string, err error) {
	// Decrypt the forward envelope
	decrypted, err := decrypter.Decrypt(ctx, encrypted)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrUnwrapFailed, err)
	}

	// Parse as forward message
	forward, err := ParseForwardFromJSON(decrypted)
	if err != nil {
		return nil, "", err
	}

	// Extract the wrapped message
	inner, err := forward.GetWrappedMessage()
	if err != nil {
		return nil, "", err
	}

	return inner, forward.Body.Next, nil
}
