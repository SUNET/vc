package helpers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/kaptinlin/jsonschema"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type testStruct struct {
	Name string `validate:"required"`
}

func TestNewError(t *testing.T) {
	type want struct {
		title   string
		details any
	}
	tts := []struct {
		name string
		have *Error
		want want
	}{
		{
			name: "TestError",
			have: NewError("TEST_ERROR"),
			want: want{
				title:   "TEST_ERROR",
				details: nil,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want.title, tt.have.Title)
			assert.Equal(t, tt.want.details, tt.have.Err)

		})
	}
}

func TestErrorString(t *testing.T) {
	tts := []struct {
		name string
		have *Error
		want string
	}{
		{
			name: "TestError",
			have: NewError("TEST_ERROR"),
			want: "Error: [TEST_ERROR]",
		},
		{
			name: "TestError with details",
			have: NewErrorDetails("TEST_ERROR", "details"),
			want: "Error: [TEST_ERROR] details",
		},
		{
			name: "nil error",
			have: (*Error)(nil),
			want: "",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.have.Error())
		})
	}
}

func TestNewErrorFromError(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		got := NewErrorFromError(nil)
		assert.Nil(t, got)
	})

	t.Run("*Error passthrough", func(t *testing.T) {
		have := NewError("CUSTOM_ERROR")
		got := NewErrorFromError(have)
		assert.Equal(t, have, got)
	})

	t.Run("json.UnmarshalTypeError", func(t *testing.T) {
		have := &json.UnmarshalTypeError{
			Value:  "bool",
			Type:   reflect.TypeFor[bool](),
			Offset: 0,
			Struct: "",
			Field:  "1",
		}
		got := NewErrorFromError(have)
		assert.Equal(t, "json_type_error", got.Title)
		assert.Equal(t, []map[string]any{
			{"actual": "bool", "expected": "bool", "field": "1"},
		}, got.Err)
	})

	t.Run("json.SyntaxError", func(t *testing.T) {
		have := &json.SyntaxError{Offset: 1}
		got := NewErrorFromError(have)
		assert.Equal(t, "json_syntax_error", got.Title)
		assert.Equal(t, map[string]any{"position": int64(1), "error": ""}, got.Err)
	})

	t.Run("validator.ValidationErrors", func(t *testing.T) {
		have := validator.ValidationErrors{}
		got := NewErrorFromError(have)
		assert.Equal(t, "validation_error", got.Title)
	})

	t.Run("jsonschema.EvaluationResult", func(t *testing.T) {
		have := &jsonschema.EvaluationResult{
			Valid:   false,
			Details: []*jsonschema.EvaluationResult{},
		}
		got := NewErrorFromError(have)
		assert.Equal(t, "document_data_schema_error", got.Title)
	})

	t.Run("non-error type", func(t *testing.T) {
		got := NewErrorFromError("just a string")
		assert.Equal(t, "internal_server_error", got.Title)
		assert.Equal(t, "just a string", got.Err)
	})

	t.Run("wrapped ErrNoDocumentFound", func(t *testing.T) {
		have := fmt.Errorf("something went wrong: %w", ErrNoDocumentFound)
		got := NewErrorFromError(have)
		assert.Equal(t, "database_error", got.Title)
		assert.Equal(t, ErrNoDocumentFound, got.Err)
	})

	t.Run("wrapped mongo.ErrNoDocuments", func(t *testing.T) {
		have := fmt.Errorf("something went wrong: %w", mongo.ErrNoDocuments)
		got := NewErrorFromError(have)
		assert.Equal(t, "database_error", got.Title)
		assert.Equal(t, ErrNoDocumentFound, got.Err)
	})

	t.Run("generic error fallthrough", func(t *testing.T) {
		have := fmt.Errorf("unexpected failure")
		got := NewErrorFromError(have)
		assert.Equal(t, "internal_server_error", got.Title)
		assert.Equal(t, "unexpected failure", got.Err)
	})
}

func TestNewErrorWithStatus(t *testing.T) {
	got := NewErrorWithStatus("NOT_FOUND", 404)
	assert.Equal(t, "NOT_FOUND", got.Title)
	assert.Equal(t, 404, got.HTTPStatus)
	assert.Nil(t, got.Err)
}

func TestNewErrorDetailsWithStatus(t *testing.T) {
	got := NewErrorDetailsWithStatus("BAD_REQUEST", "invalid input", 400)
	assert.Equal(t, "BAD_REQUEST", got.Title)
	assert.Equal(t, "invalid input", got.Err)
	assert.Equal(t, 400, got.HTTPStatus)
}

func TestFormatValidationErrors(t *testing.T) {
	v := validator.New()
	err := v.Struct(&testStruct{Name: ""})
	assert.Error(t, err)

	valErrs, ok := err.(validator.ValidationErrors)
	assert.True(t, ok)

	got := NewErrorFromError(valErrs)
	assert.Equal(t, "validation_error", got.Title)

	details, ok := got.Err.([]map[string]any)
	assert.True(t, ok)
	assert.Len(t, details, 1)
	assert.Equal(t, "Name", details[0]["field"])
	assert.Equal(t, "required", details[0]["validation"])
}

func TestFormatValidationErrorsDocumentData(t *testing.T) {
	have := &jsonschema.EvaluationResult{
		Valid: false,
		Details: []*jsonschema.EvaluationResult{
			{
				Valid:            false,
				InstanceLocation: "/b_field",
				Errors: map[string]*jsonschema.EvaluationError{
					"type_mismatch": {Code: "type_mismatch", Message: "expected string"},
				},
			},
			{
				Valid:            true,
				InstanceLocation: "/ok_field",
			},
			{
				Valid:            false,
				InstanceLocation: "/a_field",
				Errors: map[string]*jsonschema.EvaluationError{
					"required": {Code: "required", Message: "field is required"},
				},
			},
		},
	}
	got := NewErrorFromError(have)
	assert.Equal(t, "document_data_schema_error", got.Title)

	details, ok := got.Err.([]map[string]any)
	assert.True(t, ok)
	assert.Len(t, details, 2)
	// Should be sorted by location
	assert.Equal(t, "/a_field", details[0]["location"])
	assert.Equal(t, "/b_field", details[1]["location"])
}

func TestProblem404(t *testing.T) {
	got := Problem404()
	assert.NotNil(t, got)
	assert.Equal(t, 404, got.Status)
}
