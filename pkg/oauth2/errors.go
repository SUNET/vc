package oauth2

import (
	"errors"
	"net/http"
)

// OAuthError represents a structured OAuth 2.0 error response per RFC 6749 §5.2.
// When returned from handler functions, the HTTP layer renders it as:
//
//	{"error": "<code>", "error_description": "<description>"}
type OAuthError struct {
	// ErrorCode is the OAuth 2.0 error code (e.g. "invalid_client", "invalid_grant").
	ErrorCode string `json:"error"`

	// ErrorDescription is a human-readable description of the error.
	ErrorDescription string `json:"error_description,omitempty"`

	// HTTPStatus is the HTTP status code to return. Not serialized.
	HTTPStatus int `json:"-"`

	// Cause is the underlying error for internal logging.
	Cause error `json:"-"`
}

func (e *OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

func (e *OAuthError) Unwrap() error {
	return e.Cause
}

// NewOAuthError creates a new OAuthError with the given code, description, and HTTP status.
func NewOAuthError(code, description string, status int) *OAuthError {
	return &OAuthError{
		ErrorCode:        code,
		ErrorDescription: description,
		HTTPStatus:       status,
	}
}

// NewOAuthErrorWithCause wraps an underlying error in an OAuthError.
func NewOAuthErrorWithCause(code, description string, status int, cause error) *OAuthError {
	return &OAuthError{
		ErrorCode:        code,
		ErrorDescription: description,
		HTTPStatus:       status,
		Cause:            cause,
	}
}

// Standard OAuth 2.0 error code constants (RFC 6749 §4.1.2.1, §5.2)
const (
	ErrCodeInvalidRequest       = "invalid_request"
	ErrCodeInvalidClient        = "invalid_client"
	ErrCodeInvalidGrant         = "invalid_grant"
	ErrCodeUnauthorizedClient   = "unauthorized_client"
	ErrCodeUnsupportedGrantType = "unsupported_grant_type"
	ErrCodeInvalidScope         = "invalid_scope"
	ErrCodeServerError          = "server_error"
	ErrCodeInvalidDPoPProof     = "invalid_dpop_proof" // RFC 9449 §7
)

// Sentinel errors (kept for errors.Is compatibility)
var (
	ErrInvalidClient  = errors.New("invalid client")
	ErrPKCERequired   = errors.New("code_verifier required for public client")
	ErrDPoPRequired   = errors.New("DPoP header is required")
	ErrExpiredRequest = errors.New("authorization request has expired")
)

// Pre-defined OAuthError instances for common token endpoint errors
var (
	OAuthErrInvalidClient = &OAuthError{
		ErrorCode:        ErrCodeInvalidClient,
		ErrorDescription: "Client authentication failed",
		HTTPStatus:       http.StatusUnauthorized, // RFC 6749 §5.2
	}

	OAuthErrInvalidGrant = &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: "The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI",
		HTTPStatus:       http.StatusBadRequest,
	}

	OAuthErrDPoPRequired = &OAuthError{
		ErrorCode:        ErrCodeInvalidDPoPProof,
		ErrorDescription: "DPoP header is required",
		HTTPStatus:       http.StatusBadRequest, // RFC 9449 §7
	}

	OAuthErrInvalidDPoPProof = &OAuthError{
		ErrorCode:        ErrCodeInvalidDPoPProof,
		ErrorDescription: "Invalid DPoP proof",
		HTTPStatus:       http.StatusBadRequest,
	}

	OAuthErrPKCERequired = &OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: "code_verifier is required for public clients",
		HTTPStatus:       http.StatusBadRequest,
	}

	OAuthErrPKCEFailed = &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: "PKCE validation failed",
		HTTPStatus:       http.StatusBadRequest,
	}

	OAuthErrExpiredRequest = &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: "Authorization request has expired",
		HTTPStatus:       http.StatusBadRequest,
	}

	OAuthErrJTIReplay = &OAuthError{
		ErrorCode:        ErrCodeInvalidDPoPProof,
		ErrorDescription: "DPoP proof JTI has already been used",
		HTTPStatus:       http.StatusBadRequest,
	}
)
