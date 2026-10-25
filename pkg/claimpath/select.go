package claimpath

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrNoClaim is the error of a pointer that selects nothing.
var ErrNoClaim = errors.New("claimpath: the pointer selects no claim")

// ErrMismatch is the error of a pointer whose component meets a value of
// the wrong type: a key on a non-object, or null or an index on a
// non-array.
var ErrMismatch = errors.New("claimpath: the claims do not have the structure the pointer selects")

// Select processes the pointer against a JSON credential as OpenID4VP 1.0
// section 7.1 defines it, starting at the root object. A missing key or
// index drops its element from the selection. A key on a non-object and
// null or an index on a non-array are an error, and so is an empty final
// selection.
func (p Pointer) Select(root map[string]any) ([]any, error) {
	components, err := p.Components()
	if err != nil {
		return nil, err
	}
	selection := []any{root}
	for i, c := range components {
		next := make([]any, 0, len(selection))
		for _, element := range selection {
			children, err := c.children(element)
			if err != nil {
				return nil, fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
			}
			next = append(next, children...)
		}
		selection = next
	}
	if len(selection) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoClaim, p)
	}
	return selection, nil
}

// children returns what the component selects in one element.
func (c Component) children(element any) ([]any, error) {
	if c.kind == keyKind {
		object, ok := element.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("key %q on a %T", c.key, element)
		}
		if value, present := object[c.key]; present {
			return []any{value}, nil
		}
		return nil, nil
	}
	array, ok := asArray(element)
	if !ok {
		return nil, fmt.Errorf("%s on a %T", c, element)
	}
	if c.kind == allKind {
		return array, nil
	}
	if c.index < uint(len(array)) {
		return []any{array[c.index]}, nil
	}
	return nil, nil
}

// String renders the component as its JSON value.
func (c Component) String() string {
	return New(c).String()
}

// asArray returns the elements of a JSON array, whichever slice type
// holds it. A byte slice is a byte string.
func asArray(value any) ([]any, bool) {
	switch v := value.(type) {
	case []any:
		return v, true
	case []byte, nil:
		return nil, false
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

// get returns the one claim a pointer of keys and indices selects.
func (p Pointer) get(root map[string]any) (any, bool, error) {
	var current any = root
	for i, c := range p.components {
		children, err := c.children(current)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
		}
		if len(children) == 0 {
			return nil, false, nil
		}
		current = children[0]
	}
	return current, true, nil
}

// set writes value at a pointer of keys and indices, creating the objects
// a key passes through.
func (p Pointer) set(root map[string]any, value any) error {
	n := len(p.components) - 1
	var container any = root
	for i, c := range p.components[:n] {
		next, err := c.child(container, p.components[i+1])
		if err != nil {
			return fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
		}
		container = next
	}
	if err := p.components[n].put(container, value); err != nil {
		return fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, n, err)
	}
	return nil
}

// child returns the container the component selects in container, and
// creates an object at a missing key that the next component, a key,
// passes through.
func (c Component) child(container any, next Component) (any, error) {
	children, err := c.children(container)
	if err != nil {
		return nil, err
	}
	if len(children) == 1 {
		return children[0], nil
	}
	if c.kind != keyKind || next.kind != keyKind {
		return nil, fmt.Errorf("%s selects no element to write into", c)
	}
	created := map[string]any{}
	container.(map[string]any)[c.key] = created
	return created, nil
}

// put writes value at the component in container.
func (c Component) put(container any, value any) error {
	switch c.kind {
	case keyKind:
		object, ok := container.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q on a %T", c.key, container)
		}
		object[c.key] = value
		return nil
	case indexKind:
		array, ok := container.([]any)
		if !ok {
			return fmt.Errorf("%s on a %T", c, container)
		}
		if c.index >= uint(len(array)) {
			return fmt.Errorf("%s on an array of %d elements", c, len(array))
		}
		array[c.index] = value
		return nil
	}
	return fmt.Errorf("%s writes no single element", c)
}
