package httpserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A body of the wrong shape is the caller's mistake: 400 with a description,
// not the 500 an unrecognised error becomes in the status mapper.
func TestUIInteraction_MalformedBodyIs400(t *testing.T) {
	cases := map[string]string{
		"amount is a boolean": `{"dcql_query":{"credentials":[]},"payment":{"amount":true,"currency":"EUR","payee_name":"n","payee_id":"i"}}`,
		"amount is an object": `{"dcql_query":{"credentials":[]},"payment":{"amount":{"x":1},"currency":"EUR","payee_name":"n","payee_id":"i"}}`,
		"payment is a string": `{"dcql_query":{"credentials":[]},"payment":"49.99"}`,
		"not json":            `{"dcql_query":`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			engine, _ := setupUIEndpointEngine(t, &uiInteractionApiv1{replySessionID: "s"})
			req := httptest.NewRequest(http.MethodPost, "/ui/interaction", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "invalid_request")
		})
	}
}
