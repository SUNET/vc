//go:build didcomm && vc20

package agent

import "errors"

// Agent errors
var (
	// ErrAgentNotInitialized indicates the agent is not properly initialized.
	ErrAgentNotInitialized = errors.New("didcomm/agent: not initialized")

	// ErrNoPrivateKey indicates no private key is available for signing/decryption.
	ErrNoPrivateKey = errors.New("didcomm/agent: no private key available")

	// ErrNoDID indicates no DID is configured.
	ErrNoDID = errors.New("didcomm/agent: no DID configured")

	// ErrNoResolver indicates no resolver is configured.
	ErrNoResolver = errors.New("didcomm/agent: no resolver configured")

	// ErrNoEndpoint indicates no endpoint could be found for the recipient.
	ErrNoEndpoint = errors.New("didcomm/agent: no endpoint found for recipient")

	// ErrNoHandler indicates no handler is registered for the message type.
	ErrNoHandler = errors.New("didcomm/agent: no handler for message type")

	// ErrProcessingFailed indicates message processing failed.
	ErrProcessingFailed = errors.New("didcomm/agent: processing failed")
)
