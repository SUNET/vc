package routing

import "errors"

var (
	// ErrNoRoute indicates no route could be found to the recipient.
	ErrNoRoute = errors.New("didcomm/routing: no route to recipient")

	// ErrInvalidForward indicates a malformed forward message.
	ErrInvalidForward = errors.New("didcomm/routing: invalid forward message")

	// ErrMissingNext indicates a forward message is missing the 'next' field.
	ErrMissingNext = errors.New("didcomm/routing: forward message missing 'next' field")

	// ErrNoRoutingKeys indicates no routing keys found in service endpoint.
	ErrNoRoutingKeys = errors.New("didcomm/routing: no routing keys in service endpoint")

	// ErrMaxHopsExceeded indicates the route exceeds the maximum allowed hops.
	ErrMaxHopsExceeded = errors.New("didcomm/routing: maximum hops exceeded")

	// ErrUnwrapFailed indicates failure to unwrap a forward message.
	ErrUnwrapFailed = errors.New("didcomm/routing: failed to unwrap forward message")
)
