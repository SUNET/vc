package vcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func mockHappyHttServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/document", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/api/v1/document")
		assert.Equal(t, req.Method, http.MethodPost)
		_, err := rw.Write(golden.Get(t, "documentGetReplyOK.golden"))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/api/v1/document/list", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/api/v1/document/list")
		assert.Equal(t, req.Method, http.MethodPost)
		_, err := rw.Write(golden.Get(t, "documentListReplyOK.golden"))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/authorize", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/authorize")
		assert.Equal(t, req.Method, http.MethodGet)
		rw.WriteHeader(http.StatusFound)
		//assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
		_, err := rw.Write(golden.Get(t, "oidcAuthorizeReplyOK.golden"))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/op/par", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/op/par")
		assert.Equal(t, req.Method, http.MethodPost)
		//rw.WriteHeader(http.StatusFound)
		//assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
		_, err := rw.Write(golden.Get(t, "oidcAuthorizeReplyOK.golden"))
		assert.NoError(t, err)
	})

	server := httptest.NewServer(mux)
	return server
}

func mockClient(ctx context.Context, t *testing.T, url string) *Client {
	_, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	log, err := logger.New("test", "", false)
	if err != nil {
		t.FailNow()
		return nil
	}

	client, err := New(&Config{
		ApigwURL: url,
	}, log)
	if err != nil {
		t.FailNow()
		return nil
	}

	return client
}

func TestGet(t *testing.T) {
	tts := []struct {
		name                 string
		query                *DocumentGetQuery
		expected             *model.Document
		expectedDocumentData any
	}{
		{
			name: "success",
			query: &DocumentGetQuery{
				AuthenticSource: "test_authentic_source",
				Scope:           "ehic",
				DocumentID:      "test_document_id",
			},
			expected: &model.Document{
				Meta: &model.MetaData{
					AuthenticSource: "SUNET",
					Scope:           "ehic",
					DocumentID:      "test_document_id",
				},
			},
			expectedDocumentData: map[string]any{
				"personal_administrative_number": "123123123",
				"issuing_authority": map[string]any{
					"id":   "1231231",
					"name": "SUNET",
				},
				"issuing_country":  "SE",
				"date_of_expiry":   "2038-01-19",
				"date_of_issuance": "2021-01-19",
				"document_number":  "123123123",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			httpServer := mockHappyHttServer(t)
			defer httpServer.Close()

			client := mockClient(ctx, t, httpServer.URL)
			got, _, err := client.APIGW.Document.Get(ctx, tt.query)
			assert.NoError(t, err)

			tt.expected.DocumentData = tt.expectedDocumentData

			assert.Equal(t, tt.expected, got)
		})
	}
}
