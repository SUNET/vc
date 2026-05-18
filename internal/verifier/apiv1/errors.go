package apiv1

import (
	"errors"
	"net/http"
)

// OAuthError represents an OAuth 2.0/OIDC error response
// Following RFC 6749 Section 5.2 (Error Response) and
// RFC 6750 Section 3.1 (Error Codes) and
// OpenID Connect Core Section 3.1.2.6 (Authentication Error Response)
type OAuthError struct {
	// Error code as defined in OAuth 2.0 spec
	ErrorCode string `json:"error"`

	// Human-readable description
	ErrorDescription string `json:"error_description,omitempty"`

	// URI for more information
	ErrorURI string `json:"error_uri,omitempty"`

	// HTTP status code to return
	HTTPStatus int `json:"-"`

	// Original error for internal logging
	Cause error `json:"-"`
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// Unwrap returns the underlying error for errors.Is and errors.As
func (e *OAuthError) Unwrap() error {
	return e.Cause
}

// Standard OAuth 2.0 error codes
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeServerError             = "server_error"
	ErrCodeTemporarilyUnavailable  = "temporarily_unavailable"

	// OIDC specific errors
	ErrCodeInteractionRequired  = "interaction_required"
	ErrCodeLoginRequired        = "login_required"
	ErrCodeAccountSelection     = "account_selection_required"
	ErrCodeConsentRequired      = "consent_required"
	ErrCodeInvalidRequestURI    = "invalid_request_uri"
	ErrCodeInvalidRequestObject = "invalid_request_object"

	// Additional errors
	ErrCodeInvalidToken   = "invalid_token"
	ErrCodeExpiredToken   = "expired_token"
	ErrCodeSessionExpired = "session_expired"
)

// Pre-defined error variables for common cases
var (
	ErrInvalidRequest = &OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrInvalidClient = &OAuthError{
		ErrorCode:        ErrCodeInvalidClient,
		ErrorDescription: "Client authentication failed",
		HTTPStatus:       http.StatusUnauthorized,
	}

	ErrInvalidGrant = &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: "The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrUnauthorizedClient = &OAuthError{
		ErrorCode:        ErrCodeUnauthorizedClient,
		ErrorDescription: "The client is not authorized to request an authorization code or access token using this method",
		HTTPStatus:       http.StatusUnauthorized,
	}

	ErrUnsupportedGrantType = &OAuthError{
		ErrorCode:        ErrCodeUnsupportedGrantType,
		ErrorDescription: "The authorization grant type is not supported by the authorization server",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrInvalidScope = &OAuthError{
		ErrorCode:        ErrCodeInvalidScope,
		ErrorDescription: "The requested scope is invalid, unknown, or malformed",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrAccessDenied = &OAuthError{
		ErrorCode:        ErrCodeAccessDenied,
		ErrorDescription: "The resource owner or authorization server denied the request",
		HTTPStatus:       http.StatusForbidden,
	}

	ErrUnsupportedResponseType = &OAuthError{
		ErrorCode:        ErrCodeUnsupportedResponseType,
		ErrorDescription: "The authorization server does not support obtaining an authorization code using this method",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrServerError = &OAuthError{
		ErrorCode:        ErrCodeServerError,
		ErrorDescription: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
		HTTPStatus:       http.StatusInternalServerError,
	}

	ErrTemporarilyUnavailable = &OAuthError{
		ErrorCode:        ErrCodeTemporarilyUnavailable,
		ErrorDescription: "The authorization server is currently unable to handle the request due to temporary overloading or maintenance",
		HTTPStatus:       http.StatusServiceUnavailable,
	}

	ErrInvalidToken = &OAuthError{
		ErrorCode:        ErrCodeInvalidToken,
		ErrorDescription: "The access token provided is expired, revoked, malformed, or invalid for other reasons",
		HTTPStatus:       http.StatusUnauthorized,
	}

	ErrExpiredToken = &OAuthError{
		ErrorCode:        ErrCodeExpiredToken,
		ErrorDescription: "The token has expired",
		HTTPStatus:       http.StatusUnauthorized,
	}

	ErrSessionNotFound = &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: "Session not found or expired",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrSessionExpired = &OAuthError{
		ErrorCode:        ErrCodeSessionExpired,
		ErrorDescription: "The session has expired",
		HTTPStatus:       http.StatusBadRequest,
	}

	ErrInvalidVP = &OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: "Invalid verifiable presentation",
		HTTPStatus:       http.StatusBadRequest,
	}

	// ErrNotFound is a generic not found error
	ErrNotFound = errors.New("not found")

	// ErrRequestNotSupported indicates the OP does not support the request
	ErrRequestNotSupported = &OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: "The request is not supported by this server",
		HTTPStatus:       http.StatusNotFound,
	}
)

// NewOAuthError creates a new OAuth error with a custom description
func NewOAuthError(code string, description string, httpStatus int) *OAuthError {
	return &OAuthError{
		ErrorCode:        code,
		ErrorDescription: description,
		HTTPStatus:       httpStatus,
	}
}

// NewInvalidRequestError creates an invalid_request error with custom description
func NewInvalidRequestError(description string) *OAuthError {
	return &OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: description,
		HTTPStatus:       http.StatusBadRequest,
	}
}

// NewInvalidClientError creates an invalid_client error with custom description
func NewInvalidClientError(description string) *OAuthError {
	return &OAuthError{
		ErrorCode:        ErrCodeInvalidClient,
		ErrorDescription: description,
		HTTPStatus:       http.StatusUnauthorized,
	}
}

// NewInvalidGrantError creates an invalid_grant error with custom description
func NewInvalidGrantError(description string) *OAuthError {
	return &OAuthError{
		ErrorCode:        ErrCodeInvalidGrant,
		ErrorDescription: description,
		HTTPStatus:       http.StatusBadRequest,
	}
}

// NewInvalidScopeError creates an invalid_scope error with custom description
func NewInvalidScopeError(description string) *OAuthError {
	return &OAuthError{
		ErrorCode:        ErrCodeInvalidScope,
		ErrorDescription: description,
		HTTPStatus:       http.StatusBadRequest,
	}
}

// NewServerError creates a server_error with optional cause
func NewServerError(description string, cause error) *OAuthError {
	return &OAuthError{
		ErrorCode:        ErrCodeServerError,
		ErrorDescription: description,
		HTTPStatus:       http.StatusInternalServerError,
		Cause:            cause,
	}
}

// GetHTTPStatus returns the HTTP status code for an error
// Returns the OAuthError's HTTPStatus if it's an OAuthError, otherwise 500
func GetHTTPStatus(err error) int {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

// IsOAuthError checks if an error is an OAuthError
func IsOAuthError(err error) bool {
	var oauthErr *OAuthError
	return errors.As(err, &oauthErr)
}

// AsOAuthError converts an error to OAuthError, or wraps it if it's not already one
func AsOAuthError(err error) *OAuthError {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr
	}
	// Wrap unknown errors as server errors
	return NewServerError("Internal server error", err)
}
