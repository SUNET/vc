package transport

import "errors"

// Common transport errors
var (
	// ErrNoEndpoint indicates no endpoint is available.
	ErrNoEndpoint = errors.New("didcomm/transport: no endpoint available")

	// ErrConnectionFailed indicates a connection failure.
	ErrConnectionFailed = errors.New("didcomm/transport: connection failed")

	// ErrSendFailed indicates a send operation failure.
	ErrSendFailed = errors.New("didcomm/transport: send failed")

	// ErrReceiveFailed indicates a receive operation failure.
	ErrReceiveFailed = errors.New("didcomm/transport: receive failed")

	// ErrInvalidContentType indicates an unsupported content type.
	ErrInvalidContentType = errors.New("didcomm/transport: invalid content type")

	// ErrTimeout indicates a timeout.
	ErrTimeout = errors.New("didcomm/transport: timeout")

	// ErrConnectionClosed indicates the connection was closed.
	ErrConnectionClosed = errors.New("didcomm/transport: connection closed")
)
