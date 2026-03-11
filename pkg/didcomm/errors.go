package didcomm

import "errors"

// Sentinel errors for DIDComm operations.
// Following ADR-004: Use sentinel errors for expected error conditions.
var (
	// Message errors
	ErrInvalidMessage     = errors.New("didcomm: invalid message")
	ErrMissingID          = errors.New("didcomm: message missing id")
	ErrMissingType        = errors.New("didcomm: message missing type")
	ErrMissingTo          = errors.New("didcomm: message missing to")
	ErrInvalidMediaType   = errors.New("didcomm: invalid media type")
	ErrMessageExpired     = errors.New("didcomm: message expired")
	ErrInvalidAttachment  = errors.New("didcomm: invalid attachment")
	ErrAttachmentNotFound = errors.New("didcomm: attachment not found")

	// Cryptographic errors
	ErrEncryptionFailed     = errors.New("didcomm: encryption failed")
	ErrDecryptionFailed     = errors.New("didcomm: decryption failed")
	ErrSigningFailed        = errors.New("didcomm: signing failed")
	ErrVerificationFailed   = errors.New("didcomm: signature verification failed")
	ErrUnsupportedAlgorithm = errors.New("didcomm: unsupported algorithm")
	ErrInvalidKey           = errors.New("didcomm: invalid key")
	ErrKeyNotFound          = errors.New("didcomm: key not found")

	// DID resolution errors
	ErrDIDResolutionFailed  = errors.New("didcomm: DID resolution failed")
	ErrKeyAgreementNotFound = errors.New("didcomm: key agreement key not found")
	ErrServiceNotFound      = errors.New("didcomm: DIDCommMessaging service not found")
	ErrInvalidDID           = errors.New("didcomm: invalid DID")

	// Transport errors
	ErrTransportFailed  = errors.New("didcomm: transport failed")
	ErrEndpointNotFound = errors.New("didcomm: endpoint not found")
	ErrConnectionFailed = errors.New("didcomm: connection failed")
	ErrTimeout          = errors.New("didcomm: operation timed out")

	// Routing errors
	ErrRoutingFailed  = errors.New("didcomm: routing failed")
	ErrInvalidForward = errors.New("didcomm: invalid forward message")
	ErrUnwrapFailed   = errors.New("didcomm: failed to unwrap forwarded message")

	// Protocol errors
	ErrUnknownProtocol   = errors.New("didcomm: unknown protocol")
	ErrProtocolViolation = errors.New("didcomm: protocol violation")
	ErrProblemReport     = errors.New("didcomm: problem report received")
)
