package jsonpointer

import "slices"

// Pointer is an immutable RFC 6901 JSON Pointer.
type Pointer struct {
	tokens []string
}

// Root returns the root pointer.
func Root() Pointer {
	return Pointer{}
}

// FromTokens builds a pointer from raw, unescaped token strings.
func FromTokens(tokens ...string) Pointer {
	return newPointer(tokens)
}

func newPointer(tokens []string) Pointer {
	if len(tokens) == 0 {
		return Root()
	}
	return Pointer{tokens: slices.Clone(tokens)}
}

// String returns the canonical RFC 6901 string form.
func (p Pointer) String() string {
	return formatPointer(p.tokens)
}

// Tokens returns a copy of the pointer tokens.
func (p Pointer) Tokens() []string {
	return slices.Clone(p.tokens)
}

// IsRoot reports whether p points at the root value.
func (p Pointer) IsRoot() bool {
	return len(p.tokens) == 0
}

// Parent returns the parent pointer.
func (p Pointer) Parent() (Pointer, error) {
	if p.IsRoot() {
		return Pointer{}, ErrNoParent
	}
	return newPointer(p.tokens[:len(p.tokens)-1]), nil
}

// Child returns a new pointer with tokens appended.
func (p Pointer) Child(tokens ...string) Pointer {
	combined := slices.Concat(p.tokens, tokens)
	return newPointer(combined)
}

// Value resolves p against doc and returns the value.
func (p Pointer) Value(doc any) (any, error) {
	return resolveValue(doc, p)
}

// Reference resolves p against doc and returns value plus parent context.
func (p Pointer) Reference(doc any) (Reference, error) {
	return resolveReference(doc, p)
}

// Reference is a resolved value with its parent traversal context.
type Reference struct {
	value   any
	parent  any
	token   string
	pointer Pointer
}

// Value returns the resolved value.
func (r Reference) Value() any {
	return r.value
}

// Parent returns the parent container when the reference is not the root.
func (r Reference) Parent() (any, bool) {
	if r.pointer.IsRoot() {
		return nil, false
	}
	return r.parent, true
}

// Token returns the final pointer token used to reach the value.
func (r Reference) Token() string {
	return r.token
}

// Pointer returns the pointer that produced the reference.
func (r Reference) Pointer() Pointer {
	return r.pointer
}
