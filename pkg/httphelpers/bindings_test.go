package httphelpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func mockClient(ctx context.Context, t *testing.T) *Client {
	t.Helper()

	log := logger.NewSimple("httphelper")

	tracer, err := trace.NewForTesting(ctx, "httphelper", log)
	assert.NoError(t, err)

	cfg := &model.Cfg{}

	client, err := New(ctx, tracer, cfg, log)
	assert.NoError(t, err)

	return client
}

// testRequestStruct contains all binding tag types for testing.
type testRequestStruct struct {
	ID     string `uri:"id"`
	Query  string `form:"query"`
	Accept string `header:"Accept"`
}

func TestBindingRequest(t *testing.T) {
	tts := []struct {
		name       string
		path       string
		rawQuery   string
		params     gin.Params
		header     http.Header
		wantID     string
		wantQuery  string
		wantAccept string
	}{
		{
			name:   "URIBinding",
			path:   "/items/123",
			params: gin.Params{{Key: "id", Value: "123"}},
			header: http.Header{},
			wantID: "123",
		},
		{
			name:      "QueryBinding",
			path:      "/items",
			rawQuery:  "query=searchterm",
			header:    http.Header{},
			wantQuery: "searchterm",
		},
		{
			name: "HeaderBinding",
			path: "/items",
			header: http.Header{
				"Accept": []string{"application/statuslist+jwt"},
			},
			wantAccept: "application/statuslist+jwt",
		},
		{
			name:     "AllBindings",
			path:     "/items/456",
			rawQuery: "query=alltest",
			params:   gin.Params{{Key: "id", Value: "456"}},
			header: http.Header{
				"Accept": []string{"application/statuslist+cwt"},
			},
			wantID:     "456",
			wantQuery:  "alltest",
			wantAccept: "application/statuslist+cwt",
		},
		{
			name:   "EmptyValues",
			path:   "/items",
			header: http.Header{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			client := mockClient(ctx, t)
			gin.SetMode(gin.TestMode)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Request = &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Path: tt.path, RawQuery: tt.rawQuery},
				Header: tt.header,
			}
			c.Params = tt.params

			req := &testRequestStruct{}
			err := client.Binding.Request(ctx, c, req)

			assert.NoError(t, err)
			assert.Equal(t, tt.wantID, req.ID)
			assert.Equal(t, tt.wantQuery, req.Query)
			assert.Equal(t, tt.wantAccept, req.Accept)
		})
	}
}
