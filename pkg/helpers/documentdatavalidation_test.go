package helpers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/kaptinlin/jsonschema"
	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestValidateFromFile(t *testing.T) {
	tts := []struct {
		name      string
		remoteRef bool
		payload   *model.CompleteDocument
		want      error
	}{
		{
			name: "OK file",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://testdata/schema_v0.golden",
				},
				DocumentData: map[string]any{"name": "test_value", "age": 21},
			},
			want: nil,
		},
		{
			name:      "OK http",
			remoteRef: true,
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "http://%s/schema_v0",
				},
				DocumentData: map[string]any{"name": "test_value", "age": 21},
			},
			want: nil,
		},
		{
			name: "age is not a number",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://testdata/schema_v0.golden",
				},
				DocumentData: map[string]any{"name": "test_value", "age": "21"},
			},
			want: &Error{Title: "document_data_schema_error", Err: []map[string]any{{"location": "/age", "message": map[string]any{"type_mismatch": "Value is string but should be integer"}}}},
		},
		{
			name: "age is too low",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://testdata/schema_v0.golden",
				},
				DocumentData: map[string]any{"name": "test_value", "age": 19},
			},
			want: (&Error{Title: "document_data_schema_error", Err: []map[string]any{{"location": "/age", "message": map[string]any{"value_below_minimum": "19 should be at least 20"}}}}),
		},
		{
			name: "array with objects",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://testdata/schema_v1.golden",
				},
				DocumentData: map[string]any{
					"parent": []any{
						map[string]any{
							"child_1": "test_value",
							"child_2": "19",
						},
					},
				},
			},
			want: nil,
		},
	}

	server := mockValidationDocumentServer(t)
	defer server.Close()

	for i, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if i == 4 {
				fmt.Println(tt.payload.DocumentData)
			}
			ctx := t.Context()
			if tt.remoteRef {
				serverURL, err := url.Parse(server.URL)
				assert.NoError(t, err)

				tt.payload.Meta.DocumentDataValidationRef = fmt.Sprintf(tt.payload.Meta.DocumentDataValidationRef, serverURL.Host)
			}
			fmt.Println(tt.payload.Meta.DocumentDataValidationRef)

			got := ValidateDocumentData(ctx, tt.payload, logger.NewSimple("test"))
			assert.Equal(t, tt.want, got)
		})
	}
}

func mockValidationDocumentServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/schema_v0", func(w http.ResponseWriter, r *http.Request) {
		schemaFile := golden.Get(t, "schema_v0.golden")
		fmt.Fprint(w, string(schemaFile))
	})
	mux.HandleFunc("/ehic_v0", func(w http.ResponseWriter, r *http.Request) {
		schemaFile := golden.Get(t, "ehic_v0.golden")
		fmt.Fprint(w, string(schemaFile))
	})
	mux.HandleFunc("/pda1_v0", func(w http.ResponseWriter, r *http.Request) {
		schemaFile := golden.Get(t, "pda1_v0.golden")
		fmt.Fprint(w, string(schemaFile))
	})

	server := httptest.NewServer(mux)

	return server
}

func TestGetValidationSchema(t *testing.T) {
	tts := []struct {
		name             string
		locationSchema   string
		validationSchema string
	}{
		{
			name:             "OK",
			locationSchema:   "http",
			validationSchema: "schema_v0",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			server := mockValidationDocumentServer(t)
			defer server.Close()

			compiler := jsonschema.NewCompiler()

			remoteLocation := fmt.Sprintf("%s/%s", server.URL, tt.validationSchema)
			gotRemote, err := getValidationSchema(remoteLocation, compiler)
			assert.NoError(t, err)

			localLocation := fmt.Sprintf("file://testdata/%s.golden", tt.validationSchema)
			gotLocal, err := getValidationSchema(localLocation, compiler)
			assert.NoError(t, err)

			assert.Equal(t, gotRemote, gotLocal)
		})
	}
}
