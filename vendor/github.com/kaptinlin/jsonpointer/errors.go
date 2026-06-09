package jsonpointer

import "errors"

var (
	// ErrInvalidIndex is returned when an invalid array index is encountered.
	// TypeScript original code from find.ts:
	// throw new Error('INVALID_INDEX');
	ErrInvalidIndex = errors.New("invalid array index")

	// ErrNotFound is returned when a path cannot be traversed.
	// TypeScript original code from find.ts:
	// throw new Error('NOT_FOUND');
	ErrNotFound = errors.New("not found")

	// ErrNoParent is returned when trying to get parent of root path.
	// TypeScript original code from util.ts:
	// if (path.length < 1) throw new Error('NO_PARENT');
	ErrNoParent = errors.New("no parent")

	// ErrPointerInvalid is returned when a JSON Pointer string is invalid.
	// TypeScript original code from validate.ts:
	// if (pointer[0] !== '/') throw new Error('POINTER_INVALID');
	ErrPointerInvalid = errors.New("pointer invalid")

	// ErrPointerTooLong is returned when a JSON Pointer string exceeds maximum length.
	// TypeScript original code from validate.ts:
	// if (pointer.length > 1024) throw new Error('POINTER_TOO_LONG');
	ErrPointerTooLong = errors.New("pointer too long")

	// ErrInvalidPath is a TypeScript-compatibility sentinel for invalid path values.
	// Current Go APIs do not return it because Path is typed as []string.
	// TypeScript original code from validate.ts:
	// if (!isArray(path)) throw new Error('Invalid path.');
	ErrInvalidPath = errors.New("invalid path")

	// ErrPathTooLong is returned when a path array exceeds maximum length.
	// TypeScript original code from validate.ts:
	// if (path.length > 256) throw new Error('Path too long.');
	ErrPathTooLong = errors.New("path too long")

	// ErrInvalidPathStep is a TypeScript-compatibility sentinel for invalid path steps.
	// Current Go APIs do not return it because Path steps are already strings.
	// TypeScript original code from validate.ts:
	// throw new Error('Invalid path step.');
	ErrInvalidPathStep = errors.New("invalid path step")
)

var (
	// ErrIndexOutOfBounds is returned when array index is out of bounds.
	ErrIndexOutOfBounds = errors.New("array index out of bounds")

	// ErrNilPointer is returned when trying to access through nil pointer.
	ErrNilPointer = errors.New("cannot traverse through nil pointer")

	// ErrFieldNotFound is returned when trying to access a non-existent struct field.
	ErrFieldNotFound = errors.New("struct field not found")

	// ErrKeyNotFound is returned when trying to access a non-existent map key.
	ErrKeyNotFound = errors.New("map key not found")
)
