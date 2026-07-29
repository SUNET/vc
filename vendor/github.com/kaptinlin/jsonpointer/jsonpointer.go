// Package jsonpointer implements read-only JSON Pointer (RFC 6901) traversal
// for Go values.
package jsonpointer

// Parse parses a strict RFC 6901 JSON Pointer string.
func Parse(pointer string) (Pointer, error) {
	tokens, err := parsePointer(pointer)
	if err != nil {
		return Pointer{}, err
	}
	return newPointer(tokens), nil
}

// Value parses pointer and resolves it against doc.
func Value(doc any, pointer string) (any, error) {
	p, err := Parse(pointer)
	if err != nil {
		return nil, err
	}
	return p.Value(doc)
}

// ReferenceOf parses pointer and resolves it against doc with parent context.
func ReferenceOf(doc any, pointer string) (Reference, error) {
	p, err := Parse(pointer)
	if err != nil {
		return Reference{}, err
	}
	return p.Reference(doc)
}

// EscapeToken escapes a raw token for use inside a JSON Pointer string.
func EscapeToken(token string) string {
	return escapeToken(token)
}

// UnescapeToken decodes one JSON Pointer token.
func UnescapeToken(encoded string) (string, error) {
	return unescapeToken(encoded)
}
