// Package rpcert — structured trust evaluation error codes.
//
// TrustEvaluationError wraps a machine-readable code with a human message so
// callers can switch on the code to produce protocol-specific responses (AuthZen
// reason strings, ITB+ status codes, HTTP responses, etc.) without hardcoding
// error strings.
//
// The code values mirror the status strings defined in RFC003 §10.2, but the
// type lives in the general rpcert package — it is not APTITUDE-specific.
// Any caller mapping to a different protocol (e.g. OpenID4VP error codes)
// can switch on the Code field and produce its own representation.
package rpcert

import "fmt"

// TrustEvaluationErrorCode is a machine-readable outcome of a trust evaluation
// step. Callers switch on this to produce protocol-specific error responses.
type TrustEvaluationErrorCode string

const (
	// ErrCodeTrustAnchorInvalid is returned when the entity's issuer or signing
	// certificate cannot be resolved in the LoTE.
	ErrCodeTrustAnchorInvalid TrustEvaluationErrorCode = "TRUST_ANCHOR_INVALID"

	// ErrCodeCertificateInvalid is returned when a WRPAC or WRPRC certificate
	// fails structural, temporal, or cryptographic validation.
	ErrCodeCertificateInvalid TrustEvaluationErrorCode = "CERTIFICATE_INVALID"

	// ErrCodeBindingFailed is returned when the WRPAC organization_identifier
	// does not match the WRPRC sub.id (ARF RPRC_16, TS 119 475 §5.1).
	ErrCodeBindingFailed TrustEvaluationErrorCode = "BINDING_FAILED"

	// ErrCodeWrongEntitlement is returned when the RP's entitlements array does
	// not include the role required for the requested operation.
	ErrCodeWrongEntitlement TrustEvaluationErrorCode = "WRONG_ENTITLEMENT"

	// ErrCodeRegistrationInvalid is returned when the National Register lookup
	// fails or indicates the RP is not registered / is suspended.
	ErrCodeRegistrationInvalid TrustEvaluationErrorCode = "REGISTRATION_INVALID"

	// ErrCodeAttestationTypeNotRegistered is returned when the RP requests or
	// provides an attestation type not listed in its registered credentials array.
	ErrCodeAttestationTypeNotRegistered TrustEvaluationErrorCode = "ATTESTATION_TYPE_NOT_REGISTERED"

	// ErrCodeIntermediaryNotAuthorized is returned when an intermediary scenario
	// is detected but the proxy-target association cannot be proven.
	ErrCodeIntermediaryNotAuthorized TrustEvaluationErrorCode = "INTERMEDIARY_NOT_AUTHORIZED"
)

// TrustEvaluationError carries a machine-readable code plus a human message.
// Callers that need to return protocol-specific error representations switch on Code.
type TrustEvaluationError struct {
	// Code is the machine-readable error category.
	Code TrustEvaluationErrorCode

	// Message is a human-readable description suitable for audit logs and
	// deny-reason fields.
	Message string

	// Cause is the underlying error that triggered this evaluation failure, if any.
	Cause error
}

func (e *TrustEvaluationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *TrustEvaluationError) Unwrap() error { return e.Cause }

// NewTrustEvaluationError constructs a TrustEvaluationError.
func NewTrustEvaluationError(code TrustEvaluationErrorCode, msg string, cause error) *TrustEvaluationError {
	return &TrustEvaluationError{Code: code, Message: msg, Cause: cause}
}
