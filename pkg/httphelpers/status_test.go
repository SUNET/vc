package httphelpers

import (
	"errors"
	"net/http"
	"testing"
	"vc/pkg/helpers"
	"vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
)

func TestStatusCode(t *testing.T) {
	ctx := t.Context()

	t.Run("OpenID4VCI errors", func(t *testing.T) {
		tests := []struct {
			name     string
			err      *openid4vci.Error
			expected int
		}{
			{"invalid_request", &openid4vci.Error{Err: openid4vci.ErrInvalidRequest}, http.StatusBadRequest},
			{"unauthorized_client", &openid4vci.Error{Err: openid4vci.ErrUnauthorizedClient}, http.StatusUnauthorized},
			{"access_denied", &openid4vci.Error{Err: openid4vci.ErrAccessDenied}, http.StatusForbidden},
			{"server_error", &openid4vci.Error{Err: openid4vci.ErrServerError}, http.StatusInternalServerError},
			{"temporarily_unavailable", &openid4vci.Error{Err: openid4vci.ErrTemporarilyUnavailable}, http.StatusServiceUnavailable},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status := StatusCode(ctx, tt.err)
				assert.Equal(t, tt.expected, status)
			})
		}
	})

	t.Run("Helpers errors", func(t *testing.T) {
		tests := []struct {
			name     string
			err      error
			expected int
		}{
			{"not_found", helpers.ErrNoDocumentFound, http.StatusNotFound},
			{"no_identity", helpers.ErrNoIdentityFound, http.StatusNotFound},
			{"already_exists", helpers.ErrDocumentAlreadyExists, http.StatusConflict},
			{"duplicate_key", helpers.ErrDuplicateKey, http.StatusConflict},
			{"validation_failed", helpers.ErrDocumentValidationFailed, http.StatusBadRequest},
			{"revoked", helpers.ErrDocumentIsRevoked, http.StatusForbidden},
			{"internal_error", helpers.ErrInternalServerError, http.StatusInternalServerError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status := StatusCode(ctx, tt.err)
				assert.Equal(t, tt.expected, status)
			})
		}
	})

	t.Run("Error string inference", func(t *testing.T) {
		tests := []struct {
			name     string
			err      error
			expected int
		}{
			{"not_found_msg", errors.New("document not found"), http.StatusNotFound},
			{"unauthorized_msg", errors.New("unauthorized access"), http.StatusUnauthorized},
			{"forbidden_msg", errors.New("access forbidden"), http.StatusForbidden},
			{"invalid_msg", errors.New("invalid input"), http.StatusBadRequest},
			{"conflict_msg", errors.New("already exists"), http.StatusConflict},
			{"timeout_msg", errors.New("request timeout"), http.StatusRequestTimeout},
			{"unknown_msg", errors.New("some random error"), http.StatusInternalServerError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status := StatusCode(ctx, tt.err)
				assert.Equal(t, tt.expected, status)
			})
		}
	})

	t.Run("Custom helpers.Error with title", func(t *testing.T) {
		tests := []struct {
			name     string
			err      *helpers.Error
			expected int
		}{
			{"not_found_title", helpers.NewError("not_found"), http.StatusNotFound},
			{"validation_error", helpers.NewError("validation_error"), http.StatusBadRequest},
			{"already_exists", helpers.NewError("already_exists"), http.StatusConflict},
			{"internal_error", helpers.NewError("internal_server_error"), http.StatusInternalServerError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status := StatusCode(ctx, tt.err)
				assert.Equal(t, tt.expected, status)
			})
		}
	})

	t.Run("Explicit HTTP status codes", func(t *testing.T) {
		tests := []struct {
			name     string
			err      *helpers.Error
			expected int
		}{
			{"explicit_404", helpers.NewErrorWithStatus("custom_not_found", http.StatusNotFound), http.StatusNotFound},
			{"explicit_400", helpers.NewErrorWithStatus("custom_bad_request", http.StatusBadRequest), http.StatusBadRequest},
			{"explicit_403", helpers.NewErrorWithStatus("custom_forbidden", http.StatusForbidden), http.StatusForbidden},
			{"explicit_409", helpers.NewErrorWithStatus("custom_conflict", http.StatusConflict), http.StatusConflict},
			{"explicit_500", helpers.NewErrorWithStatus("custom_internal_error", http.StatusInternalServerError), http.StatusInternalServerError},
			{"explicit_501", helpers.NewErrorWithStatus("custom_not_implemented", http.StatusNotImplemented), http.StatusNotImplemented},
			{"explicit_503", helpers.NewErrorWithStatus("custom_unavailable", http.StatusServiceUnavailable), http.StatusServiceUnavailable},
			{"explicit_with_details", helpers.NewErrorDetailsWithStatus("custom_with_details", "some details", http.StatusTeapot), http.StatusTeapot},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				status := StatusCode(ctx, tt.err)
				assert.Equal(t, tt.expected, status, "Expected explicit status code to be used")
			})
		}
	})

	t.Run("Explicit status overrides inference", func(t *testing.T) {
		// Even with a title that would normally map to 404, explicit status takes precedence
		err := helpers.NewErrorWithStatus("not_found", http.StatusForbidden)
		status := StatusCode(ctx, err)
		assert.Equal(t, http.StatusForbidden, status, "Explicit status should override title-based inference")
	})
}

func TestContains(t *testing.T) {
	tests := []struct {
		name       string
		errStr     string
		substrings []string
		expected   bool
	}{
		{"matches_first", "document not found", []string{"not found", "missing"}, true},
		{"matches_second", "data is missing", []string{"not found", "missing"}, true},
		{"case_insensitive", "Document NOT FOUND", []string{"not found"}, true},
		{"no_match", "some error", []string{"not found", "missing"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.errStr, tt.substrings...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
