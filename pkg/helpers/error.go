package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/kaptinlin/jsonschema"
	"github.com/moogar0880/problems"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	// ErrDocumentIsRevoked is returned when a document is revoked
	ErrDocumentIsRevoked = NewError("DOCUMENT_IS_REVOKED")
	// ErrNoTransactionID is returned when transactionID is not present
	ErrNoTransactionID = NewError("NO_TRANSACTION_ID")

	// ErrNoDocumentFound is returned when no document is found
	ErrNoDocumentFound = NewError("NO_DOCUMENT_FOUND")

	// ErrDocumentAlreadyExists is returned when a document already exists
	ErrDocumentAlreadyExists = NewError("DOCUMENT_ALREADY_EXISTS")

	// ErrNoDocumentData is returned when no document_data is found
	ErrNoDocumentData = NewError("NO_DOCUMENT_DATA")

	// ErrNoIdentityFound is returned when no identity is found
	ErrNoIdentityFound = NewError("NO_IDENTITY_FOUND")

	// ErrIdentityMappingNamespaceRequired is returned when an identity-mapping
	// resolution names no authentic source to scope the lookup to. See SUNET/vc#507.
	ErrIdentityMappingNamespaceRequired = NewErrorWithStatus("IDENTITY_MAPPING_NAMESPACE_REQUIRED", http.StatusBadRequest)

	// ErrDuplicateKey is returned when a duplicate key is found
	ErrDuplicateKey = NewError("DUPLICATE_KEY")

	// ErrNoRevocationID is returned when no revocation_id is found
	ErrNoRevocationID = NewError("NO_REVOCATION_ID")

	// ErrPrivateKeyMissing error for empty private key
	ErrPrivateKeyMissing = NewError("ERR_PRIVATE_KEY_MISSING")

	// ErrNoKnownVCT error for no known vct
	ErrNoKnownVCT = NewError("ERR_NO_KNOWN_VCT")

	// ErrInternalServerError error for internal server error
	ErrInternalServerError = NewError("INTERNAL_SERVER_ERROR")

	// ErrDocumentValidationFailed error for document validation failed
	ErrDocumentValidationFailed = NewError("DOCUMENT_VALIDATION_FAILED")
)

// Error is a struct that represents an error
type Error struct {
	Title      string `json:"title"`
	Err        any    `json:"details"`
	HTTPStatus int    `json:"-"` // HTTP status code to return, 0 means auto-detect

	// unclassified marks an Error that NewErrorFromError built from an
	// error it recognised nothing about, by putting the raw Go error string
	// in Err. Everything else here is a shape somebody chose to publish -
	// a validation report, a JSON parse position, a sentinel - and is safe
	// to return. This one is whatever wrapping happened to say, which is
	// why the HTTP layer redacts it.
	//
	// Unexported so only this package can set it, and invisible to JSON.
	unclassified bool
}

// IsUnclassified reports whether this Error carries the text of an error
// nothing recognised, rather than a shape chosen for publication. The
// distinction lives here rather than in a type switch at the HTTP boundary
// so there is one list of what counts as classified - the one in
// NewErrorFromError - instead of two that have to agree.
func (e *Error) IsUnclassified() bool {
	return e != nil && e.unclassified
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("Error: [%s] %+v", e.Title, e.Err)
	}
	return fmt.Sprintf("Error: [%s]", e.Title)
}

// ErrorResponse is a struct that represents an error response in JSON from REST API
type ErrorResponse struct {
	Error *Error `json:"error"`
}

func NewError(title string) *Error {
	return &Error{Title: title}
}

func NewErrorDetails(title string, err any) *Error {
	return &Error{Title: title, Err: err}
}

// NewErrorWithStatus creates a new Error with an explicit HTTP status code
func NewErrorWithStatus(title string, httpStatus int) *Error {
	return &Error{Title: title, HTTPStatus: httpStatus}
}

// NewErrorDetailsWithStatus creates a new Error with details and an explicit HTTP status code
func NewErrorDetailsWithStatus(title string, err any, httpStatus int) *Error {
	return &Error{Title: title, Err: err, HTTPStatus: httpStatus}
}

// NewErrorFromError creates a new Error from an error or evaluation result
func NewErrorFromError(v any) *Error {
	if v == nil {
		return nil
	}

	if vErr, ok := v.(*jsonschema.EvaluationResult); ok {
		return &Error{Title: "document_data_schema_error", Err: formatValidationErrorsDocumentData(vErr)}
	}

	err, ok := v.(error)
	if !ok {
		return &Error{Title: "internal_server_error", Err: fmt.Sprintf("%+v", v), unclassified: true}
	}

	if pbErr, ok := err.(*Error); ok {
		return pbErr
	}

	// errors.As, not a direct type assertion. A handler that adds context
	// with %w - "parsing the credential request: <json syntax error>",
	// which is ordinary Go - used to fall past every branch here and out
	// the catch-all. That was survivable while the catch-all returned the
	// error text; now that it redacts, it turns a client error into an
	// opaque internal_server_error and the caller loses the parse offset
	// that would have told them what to fix.
	if jsonUnmarshalTypeError, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return &Error{Title: "json_type_error", Err: formatJSONUnmarshalTypeError(jsonUnmarshalTypeError)}
	}
	if jsonSyntaxError, ok := errors.AsType[*json.SyntaxError](err); ok {
		return &Error{Title: "json_syntax_error", Err: map[string]any{"position": jsonSyntaxError.Offset, "error": jsonSyntaxError.Error()}}
	}
	if validatorErr, ok := errors.AsType[validator.ValidationErrors](err); ok {
		return &Error{Title: "validation_error", Err: formatValidationErrors(validatorErr)}
	}

	if errors.Is(err, mongo.ErrNoDocuments) || errors.Is(err, ErrNoDocumentFound) {
		return &Error{Title: "database_error", Err: ErrNoDocumentFound}
	}
	if mongo.IsDuplicateKeyError(err) {
		fmt.Println("Duplicate key error")
		return &Error{Title: "database_error", Err: ErrDocumentAlreadyExists}
	}

	// A sentinel wrapped with %w - e.g. ErrIdentityMappingNamespaceRequired from
	// ResolveIdentifier - keeps its named title instead of collapsing to
	// internal_server_error below.
	if wrapped, ok := errors.AsType[*Error](err); ok {
		return wrapped
	}

	return &Error{Title: "internal_server_error", Err: err.Error(), unclassified: true}
}

func formatValidationErrors(err validator.ValidationErrors) []map[string]any {
	v := make([]map[string]any, 0)
	for _, e := range err {
		splits := strings.SplitN(e.Namespace(), ".", 2)
		v = append(v, map[string]any{
			"field":           e.Field(),
			"namespace":       splits[1],
			"type":            e.Kind().String(),
			"validation":      e.Tag(),
			"validationParam": e.Param(),
		})
	}
	return v
}

func formatValidationErrorsDocumentData(err *jsonschema.EvaluationResult) []map[string]any {
	reply := []map[string]any{}
	for _, e := range err.Details {
		if !e.Valid {
			errMsg := map[string]any{}
			for _, eV := range e.Errors {
				errMsg[eV.Code] = eV.Error()
			}
			reply = append(reply, map[string]any{
				"location": e.InstanceLocation,
				"message":  errMsg,
			})
		}
	}

	sort.Slice(reply, func(i, j int) bool {
		return reply[i]["location"].(string) < reply[j]["location"].(string)
	})

	return reply
}

func formatJSONUnmarshalTypeError(err *json.UnmarshalTypeError) []map[string]any {
	return []map[string]any{
		{
			"field":    err.Field,
			"expected": err.Type.Kind().String(),
			"actual":   err.Value,
		},
	}
}

func Problem404() *problems.Problem {
	problem := problems.NewStatusProblem(404)

	return problem
}
