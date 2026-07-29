package jsonpointer

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidPointer is returned when a JSON Pointer string is invalid.
	ErrInvalidPointer = errors.New("invalid pointer")
)

var (
	// ErrInvalidIndex is returned when an array token is not a canonical index.
	ErrInvalidIndex = errors.New("invalid array index")

	// ErrIndexOutOfBounds is returned when an array index is outside the array.
	ErrIndexOutOfBounds = errors.New("array index out of bounds")

	// ErrKeyNotFound is returned when a map key is missing.
	ErrKeyNotFound = errors.New("map key not found")

	// ErrNilPointer is returned when traversal must dereference a nil pointer.
	ErrNilPointer = errors.New("cannot traverse through nil pointer")

	// ErrNotTraversable is returned when a value cannot consume a pointer token.
	ErrNotTraversable = errors.New("value is not traversable")

	// ErrNoParent is returned when asking for the parent of the root pointer.
	ErrNoParent = errors.New("no parent")
)

// Error wraps a traversal failure with machine-readable pointer context.
type Error struct {
	cause   error
	pointer Pointer
	token   string
	depth   int
}

func newError(cause error, pointer Pointer, depth int) *Error {
	token := ""
	if depth >= 0 && depth < len(pointer.tokens) {
		token = pointer.tokens[depth]
	}
	return &Error{
		cause:   cause,
		pointer: pointer,
		token:   token,
		depth:   depth,
	}
}

// Error returns a human-readable error message.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.depth < 0 {
		return fmt.Sprintf("%s at %s", e.cause, e.pointer.String())
	}
	return fmt.Sprintf("%s at %s token %q", e.cause, e.pointer.String(), e.token)
}

// Unwrap returns the sentinel cause for errors.Is checks.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Pointer returns the requested pointer being resolved.
func (e *Error) Pointer() Pointer {
	if e == nil {
		return Root()
	}
	return e.pointer
}

// Token returns the token being resolved when the error occurred.
func (e *Error) Token() string {
	if e == nil {
		return ""
	}
	return e.token
}

// Depth returns the zero-based token depth where the error occurred.
func (e *Error) Depth() int {
	if e == nil {
		return -1
	}
	return e.depth
}
