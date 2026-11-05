package httphelpers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// StatusCode returns the status code of the error
func StatusCode(ctx context.Context, err error) int {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	// Check for specific error types first
	switch err := err.(type) {
	case *oauth2.OAuthError:
		return err.HTTPStatus
	case *openid4vci.Error:
		return openid4vci.StatusCode(err)
	case *helpers.Error:
		// If HTTPStatus is explicitly set, use it
		if err.HTTPStatus != 0 {
			return err.HTTPStatus
		}

		// Map specific helper errors to HTTP status codes
		switch err {
		case helpers.ErrNoDocumentFound, helpers.ErrNoIdentityFound:
			return http.StatusNotFound
		case helpers.ErrIdentityMappingNamespaceRequired:
			return http.StatusBadRequest
		case helpers.ErrDocumentAlreadyExists, helpers.ErrDuplicateKey:
			return http.StatusConflict
		case helpers.ErrDocumentValidationFailed:
			return http.StatusBadRequest
		case helpers.ErrDocumentIsRevoked:
			return http.StatusForbidden
		case helpers.ErrNoTransactionID, helpers.ErrNoDocumentData, helpers.ErrNoRevocationID, helpers.ErrPrivateKeyMissing, helpers.ErrNoKnownVCT:
			return http.StatusBadRequest
		case helpers.ErrInternalServerError:
			return http.StatusInternalServerError
		default:
			// Check if the wrapped error is a known error type
			if errHelper, ok := err.Err.(*helpers.Error); ok {
				switch errHelper {
				case helpers.ErrDocumentAlreadyExists, helpers.ErrDuplicateKey:
					return http.StatusConflict
				case helpers.ErrNoDocumentFound, helpers.ErrNoIdentityFound:
					return http.StatusNotFound
				}
			}

			// Check error title/message for other helpers.Error instances
			return inferStatusFromErrorTitle(err.Title)
		}
	}

	// A *helpers.Error reached through %w, which the type switch above
	// cannot see.
	//
	// NewErrorFromError already unwraps - it uses errors.AsType - so the
	// RESPONSE BODY of a wrapped classified error is correct today while
	// the status is decided down in inferStatusFromErrorString, from
	// whatever words happen to appear in the wrapper's text. That is not
	// a 500 by default so much as a status chosen by prose: a 400 refusal
	// reads as 401 when the wrapper says "token" and as 404 when it says
	// "missing". A client acting on 401 re-authenticates in response to a
	// request it should simply not repeat.
	//
	// Placed after the sentinel checks below it would be equivalent, and
	// before them is clearer: this is the general case those four
	// errors.Is lines are specific instances of. They were each added
	// when a particular wrapped sentinel surfaced wrong, one at a time;
	// this is the rule they were approximating.
	if classified, ok := errors.AsType[*helpers.Error](err); ok {
		return StatusCode(ctx, classified)
	}

	// Check if it's wrapped in one of our known errors
	if errors.Is(err, helpers.ErrNoDocumentFound) || errors.Is(err, helpers.ErrNoIdentityFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, helpers.ErrIdentityMappingNamespaceRequired) {
		return http.StatusBadRequest
	}
	if errors.Is(err, helpers.ErrDocumentAlreadyExists) || errors.Is(err, helpers.ErrDuplicateKey) {
		return http.StatusConflict
	}
	if errors.Is(err, helpers.ErrInternalServerError) {
		return http.StatusInternalServerError
	}

	// Check for http.MaxBytesError (request body exceeded size limit)
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return http.StatusRequestEntityTooLarge
	}

	// Check for OAuth2 sentinel errors (fallback for code that hasn't migrated to OAuthError yet)
	if errors.Is(err, oauth2.ErrInvalidClient) {
		return http.StatusUnauthorized // RFC 6749 §5.2
	}
	if errors.Is(err, oauth2.ErrPKCERequired) {
		return http.StatusBadRequest
	}
	if errors.Is(err, oauth2.ErrDPoPRequired) {
		return http.StatusBadRequest
	}
	if errors.Is(err, oauth2.ErrExpiredRequest) {
		return http.StatusBadRequest
	}
	if errors.Is(err, oauth2.ErrJTIReplay) {
		return http.StatusBadRequest
	}

	// Try to infer status from error content
	errStr := err.Error()
	return inferStatusFromErrorString(errStr)
}

// inferStatusFromErrorTitle maps error titles to HTTP status codes
func inferStatusFromErrorTitle(title string) int {
	title = strings.ToLower(title)

	switch {
	case contains(title, "not_found", "no_document", "no_identity"):
		return http.StatusNotFound
	case contains(title, "unauthorized", "authentication"):
		return http.StatusUnauthorized
	case contains(title, "forbidden", "revoked", "access_denied", "not_allowed"):
		return http.StatusForbidden
	case contains(title, "invalid", "validation", "bad_request", "malformed"):
		return http.StatusBadRequest
	case contains(title, "conflict", "already_exists", "duplicate"):
		return http.StatusConflict
	case contains(title, "internal_server_error", "server_error"):
		return http.StatusInternalServerError
	case contains(title, "not_implemented", "unsupported"):
		return http.StatusNotImplemented
	case contains(title, "timeout", "unavailable"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// inferStatusFromErrorString infers HTTP status code from error message
func inferStatusFromErrorString(errStr string) int {
	switch {
	case contains(errStr, "not found", "no document", "missing"):
		return http.StatusNotFound
	case contains(errStr, "unauthorized", "authentication", "token"):
		return http.StatusUnauthorized
	case contains(errStr, "forbidden", "access denied", "permission", "revoked"):
		return http.StatusForbidden
	case contains(errStr, "invalid", "validation", "malformed", "bad request"):
		return http.StatusBadRequest
	case contains(errStr, "conflict", "already exists", "duplicate"):
		return http.StatusConflict
	case contains(errStr, "unsupported", "not implemented"):
		return http.StatusNotImplemented
	case contains(errStr, "timeout", "deadline"):
		return http.StatusRequestTimeout
	default:
		// Default to 500 Internal Server Error for unrecognized errors
		return http.StatusInternalServerError
	}
}

// contains checks if any of the substrings appear in the error string (case-insensitive)
func contains(errStr string, substrings ...string) bool {
	errLower := strings.ToLower(errStr)
	for _, substr := range substrings {
		if strings.Contains(errLower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
