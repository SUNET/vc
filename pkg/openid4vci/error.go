package openid4vci

import (
	"fmt"
	"net/http"
)

// Error is the error response
type Error struct {
	Err              string `json:"error"`
	ErrorDescription any    `json:"error_description,omitempty"`
}

func (e *Error) Error() string {
	if e.ErrorDescription != nil {
		return fmt.Sprintf("%s: %v", e.Err, e.ErrorDescription)
	}
	return e.Err
}

// Credential errors
const (
	// ErrInvalidCredentialRequest The Credential Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed.
	ErrInvalidCredentialRequest string = "invalid_credential_request" // #nosec G101

	// ErrUnsupportedCredentialType Requested Credential type is not supported.
	ErrUnsupportedCredentialType = "unsupported_credential_type"

	// ErrUnsupportedCredentialFormat Requested Credential Format is not supported.
	ErrUnsupportedCredentialFormat = "unsupported_credential_format"

	// ErrInvalidProof The proof or proofs parameter in the Credential Request is invalid: (1) if both fields are missing, or (2) both are present simultaneously, or (3) one of the provided key proofs is invalid, or (4) if at least one of the key proofs does not contain a c_nonce value (refer to Section 7.2).
	ErrInvalidProof = "invalid_proof"

	// ErrInvalidNonce The proof or proofs parameter in the Credential Request uses an invalid nonce: at least one of the key proofs contains an invalid c_nonce value. The wallet should retrieve a new c_nonce value (refer to Section 7).
	ErrInvalidNonce = "invalid_nonce"

	// ErrInvalidEncryptionParameters This error occurs when the encryption parameters in the Credential Request are either invalid or missing. In the latter case, it indicates that the Credential Issuer requires the Credential Response to be sent encrypted, but the Credential Request does not contain the necessary encryption parameters.
	ErrInvalidEncryptionParameters = "invalid_encryption_parameters"

	// ErrUnknownCredentialConfiguration The credential_configuration_id in the Credential Request is not recognized by the Credential Issuer.
	ErrUnknownCredentialConfiguration = "unknown_credential_configuration"

	// ErrUnknownCredentialIdentifier The credential_identifier in the Credential Request is not recognized by the Credential Issuer.
	ErrUnknownCredentialIdentifier = "unknown_credential_identifier"

	// ErrCredentialRequestDenied The Credential Request has not been accepted by the Credential Issuer.
	ErrCredentialRequestDenied = "credential_request_denied" // #nosec G101
)

const (
	// ErrInvalidRequest The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
	ErrInvalidRequest = "invalid_request"

	// ErrUnauthorizedClient  The client is not authorized to request an authorization code using this method.
	ErrUnauthorizedClient = "unauthorized_client"

	// ErrAccessDenied The resource owner or authorization server denied the request.
	ErrAccessDenied = "access_denied"

	// ErrUnsupportedResponseType The authorization server does not support obtaining an authorization code using this method.
	ErrUnsupportedResponseType = "unsupported_response_type"

	// ErrInvalidScope The requested scope is invalid, unknown, or malformed.
	ErrInvalidScope = "invalid_scope"

	// ErrServerError The authorization server encountered an unexpected condition that prevented it from fulfilling the request.(This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)
	ErrServerError = "server_error"

	// ErrTemporarilyUnavailable The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
	ErrTemporarilyUnavailable = "temporarily_unavailable"
)

// Token errors
const (

	// ErrTokenInvalidRequest * The Authorization Server does not expect a Transaction Code in the Pre-Authorized Code Flow but the Client provides a Transaction Code.
	// * The Authorization Server expects a Transaction Code in the Pre-Authorized Code Flow but the Client does not provide a Transaction Code.
	ErrTokenInvalidRequest = "invalid_request"

	// ErrTokenInvalidGrant * The Authorization Server expects a Transaction Code in the Pre-Authorized Code Flow but the Client provides the wrong Transaction Code.
	// * The End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired.
	ErrTokenInvalidGrant = "invalid_grant"

	// ErrTokenInvalidClient * The Client tried to send a Token Request with a Pre-Authorized Code without a Client ID but the Authorization Server does not support anonymous access.
	ErrTokenInvalidClient = "invalid_client"

	// ErrTokenUnauthorizedClient The client is not authorized to request an authorization code using this method.
	ErrTokenUnauthorizedClient = "unauthorized_client"

	// ErrTokenAccessDenied The resource owner or authorization server denied the request.
	ErrTokenAccessDenied = "access_denied"

	// ErrTokenUnsupportedResponseType the authorization server does not support obtaining an authorization code using this method.
	ErrTokenUnsupportedResponseType = "unsupported_response_type"

	// ErrTokenInvalidScope the requested scope is invalid, unknown, or malformed.
	ErrTokenInvalidScope = "invalid_scope"

	// ErrTokenServerError the authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)
	ErrTokenServerError = "server_error"

	// ErrTokenTemporarilyUnavailable The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
	ErrTokenTemporarilyUnavailable = "temporarily_unavailable"
)

// Notification errors
const (
	// InvalidNotificationID  invalid_notification_id: The notification_id in the Notification Request was invalid.
	InvalidNotificationID = "invalid_notification_id"

	// InvalidNotificationRequest invalid_notification_request: The Notification Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed.
	InvalidNotificationRequest = "invalid_notification_request"
)

// StatusCode returns the HTTP status code for the error
func StatusCode(err *Error) int {
	switch err.Err {
	case ErrInvalidScope, ErrUnsupportedResponseType, ErrInvalidCredentialRequest, ErrUnsupportedCredentialType, ErrUnsupportedCredentialFormat, ErrInvalidProof, ErrInvalidNonce, ErrInvalidEncryptionParameters, ErrInvalidRequest, ErrCredentialRequestDenied, InvalidNotificationID, ErrUnknownCredentialConfiguration, ErrUnknownCredentialIdentifier:
		return http.StatusBadRequest
	case ErrUnauthorizedClient:
		return http.StatusUnauthorized
	case ErrAccessDenied:
		return http.StatusForbidden
	case ErrServerError:
		return http.StatusInternalServerError
	case ErrTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	default:
		// Default to 400 Bad Request for unknown OpenID4VCI errors
		return http.StatusBadRequest
	}
}
