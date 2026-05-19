// Package jsonpointer implements read-only JSON Pointer (RFC 6901) traversal helpers for Go values.
//
// The implementation follows https://github.com/jsonjoy-com/json-pointer behavior.
// Public traversal APIs return errors for invalid paths and unsupported access patterns.
package jsonpointer

// Get retrieves a value from document using string path components.
// Returns errors for invalid operations, similar to Find function.
func Get(doc any, path ...string) (any, error) {
	return get(doc, Path(path))
}

// Find locates a reference in document using string path components.
// Returns errors for invalid operations.
func Find(doc any, path ...string) (*Reference, error) {
	return find(doc, Path(path))
}

// GetByPointer retrieves a value from document using JSON Pointer string.
// Returns errors for invalid operations.
func GetByPointer(doc any, pointer string) (any, error) {
	path := Parse(pointer)
	return get(doc, path)
}

// FindByPointer locates a reference in document using JSON Pointer string.
func FindByPointer(doc any, pointer string) (*Reference, error) {
	return findByPointer(pointer, doc)
}

// Parse parses a JSON Pointer string to a path array.
func Parse(pointer string) Path {
	return parseJSONPointer(pointer)
}

// Format formats string path components into a JSON Pointer string.
func Format(path ...string) string {
	return formatJSONPointer(Path(path))
}

// Escape escapes special characters in a path component.
func Escape(component string) string {
	return escapeComponent(component)
}

// Unescape unescapes special characters in a path component.
func Unescape(component string) string {
	return unescapeComponent(component)
}

// Validate validates a JSON Pointer string.
func Validate(pointer string) error {
	return validatePointerString(pointer)
}

// ValidatePath validates a path array.
func ValidatePath(path Path) error {
	return validatePath(path)
}
