package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A body of the wrong shape is the caller's mistake: 400 with a description,
// not the 500 an unrecognised error becomes in the status mapper.
func TestUIInteraction_MalformedBodyIs400(t *testing.T) {
	cases := map[string]struct {
		body string
		// incomplete: the body ends short of its Content-Length.
		incomplete bool
	}{
		"payment is a string": {body: `{"dcql_query":{"credentials":[]},"payment":"49.99"}`},
		"not json":            {body: `{"dcql_query":`},
		"cut short":           {body: `{"dcql_query":{"credentials":[]}}`, incomplete: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			engine, _ := setupUIEndpointEngine(t, &uiInteractionApiv1{replySessionID: "s"})
			req := httptest.NewRequest(http.MethodPost, "/ui/interaction", bytes.NewReader([]byte(tc.body)))
			if tc.incomplete {
				req.Body = io.NopCloser(io.MultiReader(bytes.NewReader([]byte(tc.body)), iotest.ErrReader(io.ErrUnexpectedEOF)))
				req.ContentLength = int64(len(tc.body)) + 1
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "invalid_request")
		})
	}
}
