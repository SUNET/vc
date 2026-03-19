package helpers

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

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
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.have.Error())
		})
	}
}

func TestNewErrorFromError(t *testing.T) {
	tts := []struct {
		name string
		have error
		want *Error
	}{
		{
			name: "json.UnmarshalTypeError",
			have: &json.UnmarshalTypeError{
				Value:  "bool",
				Type:   reflect.TypeFor[bool](),
				Offset: 0,
				Struct: "",
				Field:  "1",
			},
			want: &Error{
				Title: "json_type_error",
				Err: []map[string]any{
					{
						"actual":   "bool",
						"expected": "bool",
						"field":    "1",
					},
				},
			},
		},
		{
			name: "json.SyntaxError",
			have: &json.SyntaxError{
				Offset: 1,
			},
			want: &Error{
				Title: "json_syntax_error",
				Err:   map[string]any{"position": int64(1), "error": ""},
			},
		},
		{
			name: "validator.ValidationErrors",
			have: validator.ValidationErrors{},
			want: &Error{
				Title: "validation_error",
				Err:   TestNewError,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "json.UnmarshalTypeError":
				have := tt.have.(*json.UnmarshalTypeError)
				got := NewErrorFromError(have)
				assert.Equal(t, tt.want, got)

			case "json.SyntaxError":
				have := tt.have.(*json.SyntaxError)
				got := NewErrorFromError(have)
				assert.Equal(t, tt.want, got)

			case "validator.ValidationErrors":
				t.Skip("TODO(masv): Skip this test case for now")
				have := tt.have.(validator.ValidationErrors)
				got := NewErrorFromError(have)
				assert.Equal(t, tt.want, got)
			default:
				t.Errorf("Test case not implemented")
			}
		})
	}
}
