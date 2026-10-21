package httphelpers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A classified error reached through %w must keep its status.
//
// The wrapper's WORDING is the thing under test. Before this unwrapped,
// a wrapped *helpers.Error fell past the type switch and all the way to
// inferStatusFromErrorString, which keyword-matches the concatenated
// message - so the status was decided by whatever prose the wrapper
// happened to contain, not by the error. A 400 refusal read as 401 when
// the wrapper said "token", and a client acting on 401 re-authenticates
// in response to a request it should simply not repeat.
func TestStatusCodeUnwrapsAClassifiedError(t *testing.T) {
	refusal := helpers.NewErrorDetailsWithStatus("zkp_req_issuer_key_set_size", "two keys, one expected", http.StatusBadRequest)

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"returned directly", refusal},
		{"wrapped with no keyword in the wrapper", fmt.Errorf("scope nym: %w", refusal)},
		{"wrapped where the wrapper says invalid", fmt.Errorf("scope nym: invalid presentation: %w", refusal)},
		{"wrapped where the wrapper says token", fmt.Errorf("scope nym: bad token: %w", refusal)},
		{"wrapped where the wrapper says missing", fmt.Errorf("scope nym: missing field: %w", refusal)},
		{"wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", refusal))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusBadRequest, StatusCode(context.Background(), tc.err),
				"the status must come from the error, not from the wrapper's wording")
		})
	}
}

// Not only 400: whatever status the classified error carries survives.
func TestStatusCodeUnwrapsEveryClassifiedStatus(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError,
	} {
		classified := helpers.NewErrorDetailsWithStatus("some_code", "detail", status)
		assert.Equal(t, status, StatusCode(context.Background(), fmt.Errorf("context: %w", classified)))
	}
}

// A classified error with no explicit status still infers from its TITLE
// when wrapped, the same way it does when returned directly - the title
// is a shape somebody chose, unlike the wrapper's prose.
func TestStatusCodeInfersFromTheTitleWhenWrapped(t *testing.T) {
	noStatus := helpers.NewErrorDetails("document_not_found", "nope")
	assert.Equal(t,
		StatusCode(context.Background(), noStatus),
		StatusCode(context.Background(), fmt.Errorf("loading the document: %w", noStatus)),
		"wrapping must not change the answer")
}

// An error nothing recognises is still a 500. The fix must not turn
// every unexpected failure into a client error.
func TestStatusCodeLeavesUnclassifiedErrorsAlone(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError,
		StatusCode(context.Background(), errors.New("something went wrong in a way nobody modelled")))
	assert.Equal(t, http.StatusInternalServerError,
		StatusCode(context.Background(), fmt.Errorf("while doing a thing: %w", errors.New("nothing recognisable"))))
}

// The four sentinel errors.Is checks this generalises are instances of
// the same rule, and must keep answering as they did.
func TestStatusCodeKeepsTheSentinelAnswers(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{helpers.ErrNoDocumentFound, http.StatusNotFound},
		{helpers.ErrNoIdentityFound, http.StatusNotFound},
		{helpers.ErrDocumentAlreadyExists, http.StatusConflict},
		{helpers.ErrDuplicateKey, http.StatusConflict},
		{helpers.ErrInternalServerError, http.StatusInternalServerError},
	} {
		require.NotNil(t, tc.err)
		assert.Equal(t, tc.want, StatusCode(context.Background(), tc.err), "%v direct", tc.err)
		assert.Equal(t, tc.want, StatusCode(context.Background(), fmt.Errorf("context: %w", tc.err)), "%v wrapped", tc.err)
	}
}
