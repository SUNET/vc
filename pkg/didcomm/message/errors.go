package message

import "errors"

// Sentinel errors for message operations.
var (
	ErrInvalidMessage    = errors.New("didcomm: invalid message")
	ErrMissingID         = errors.New("didcomm: message missing id")
	ErrMissingType       = errors.New("didcomm: message missing type")
	ErrMessageExpired    = errors.New("didcomm: message expired")
	ErrInvalidAttachment = errors.New("didcomm: invalid attachment")
)
