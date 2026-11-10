package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatastoreListRestrictedToAllowedSources sends list requests through the
// production middleware chain, endpoint and apiv1 handler. An identity holds
// one document in source A and one in source B; alice may read only source A.
func TestDatastoreListRestrictedToAllowedSources(t *testing.T) {
	chain := newReadChain(t, []*model.MetaData{
		{AuthenticSource: "A", Scope: "pid", DocumentID: "doc-of-A"},
		{AuthenticSource: "B", Scope: "pid", DocumentID: "doc-of-B"},
	}, []string{
		`(vc (service apigw)(method *)(path *)(subject alice)(authentic_source A)(scope pid))`,
		`(vc (service apigw)(method *)(path *)(subject bob)(authentic_source *)(scope *))`,
	}, true)
	sessionAs, tokenOf := chain.sessionAs, chain.tokenOf

	for _, row := range []struct {
		name       string
		authorize  func(*http.Request)
		body       string
		header     map[string]string
		wantStatus int
		wantDocs   []string
	}{
		{
			name:       "session limited to A, no selector",
			authorize:  sessionAs("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "session limited to A, reach B in a header",
			authorize:  sessionAs("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			header:     map[string]string{"Reach": "B"},
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "session with a wildcard rule, no selector",
			authorize:  sessionAs("bob"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A", "doc-of-B"},
		},
		{
			name:       "token limited to A, no selector",
			authorize:  tokenOf("alice"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "token limited to A, selector A",
			authorize:  tokenOf("alice"),
			body:       `{"identity_mapping_id":"person","authentic_source":"A","scope":"pid"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A"},
		},
		{
			name:       "token with a wildcard rule, no selector",
			authorize:  tokenOf("bob"),
			body:       `{"identity_mapping_id":"person"}`,
			wantStatus: http.StatusOK,
			wantDocs:   []string{"doc-of-A", "doc-of-B"},
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/datastore/list", strings.NewReader(row.body))
			req.Header.Set("Content-Type", "application/json")
			for name, value := range row.header {
				req.Header.Set(name, value)
			}
			row.authorize(req)

			reply := httptest.NewRecorder()
			chain.engine.ServeHTTP(reply, req)
			require.Equal(t, row.wantStatus, reply.Code, reply.Body.String())
			if row.wantStatus != http.StatusOK {
				return
			}

			var listed apiv1.DatastoreListReply
			require.NoError(t, json.Unmarshal(reply.Body.Bytes(), &listed))
			received := make([]string, 0, len(listed.Data))
			for _, doc := range listed.Data {
				received = append(received, doc.Meta.DocumentID)
			}
			assert.ElementsMatch(t, row.wantDocs, received, "documents received")
		})
	}
}

// TestReachUnreachableFromBinders offers a reach through every channel
// Binding.Request reads, on every request type that holds one.
func TestReachUnreachableFromBinders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := t.Context()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	httpHelpers, err := httphelpers.New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, err)

	offered := url.Values{"Reach": {`{"grants":[{"source":"B","scope":"pid"}]}`}, "reach": {"everything"}, "-": {"B"}}
	channels := map[string]func() *http.Request{
		"header": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			for name, values := range offered {
				req.Header.Set(name, values[0])
			}
			return req
		},
		"query": func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/?"+offered.Encode(), nil)
		},
		"form": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(offered.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req
		},
		"json": func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Reach":{"grants":[{"source":"B","scope":"pid"}]},"reach":"everything","-":["B"]}`))
			req.Header.Set("Content-Type", "application/json")
			return req
		},
	}

	for channel, newRequest := range channels {
		t.Run(channel, func(t *testing.T) {
			bind := func(request any) {
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = newRequest()
				// A failed validation of an unrelated required field leaves
				// the request bound, which is what this test inspects.
				err := httpHelpers.Binding.Request(ctx, c, request)
				t.Log("binding result:", err)
			}

			list := &apiv1.DatastoreListRequest{}
			bind(list)
			assert.True(t, list.Reach.Nothing())

			search := &apiv1.DatastoreSearchRequest{}
			bind(search)
			assert.True(t, search.Reach.Nothing())

			mappingSearch := &apiv1.IdentityMappingSearchRequest{}
			bind(mappingSearch)
			assert.True(t, mappingSearch.Reach.Nothing())
		})
	}
}
