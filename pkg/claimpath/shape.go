package claimpath

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Shape is how a claims map holds the claims of a credential. A pointer
// names a claim of the credential; the shape locates that claim in the
// map.
//
//   - Nested holds a JSON-based credential (SD-JWT VC, W3C) as its JSON
//     object.
//   - MDocQualified holds a presented ISO mdoc: one flat key
//     "<namespace>.<element>" per data element.
//   - MDocElements holds the document data of an ISO mdoc: one key per
//     data element identifier, in a namespace the MDDL declares.
type Shape struct {
	kind shapeKind
	// namespaces maps an element identifier to the namespaces that
	// declare it, sorted, for MDocElements.
	namespaces map[string][]string
	// declared holds the namespaces the MDDL declares, for MDocElements.
	declared map[string]bool
}

type shapeKind uint8

const (
	nestedShape shapeKind = iota + 1
	mdocQualifiedShape
	mdocElementsShape
)

// Nested returns the shape of a JSON-based credential.
func Nested() Shape { return Shape{kind: nestedShape} }

// MDocQualified returns the shape of a presented mdoc.
func MDocQualified() Shape {
	return Shape{kind: mdocQualifiedShape}
}

// MDocElements returns the shape of mdoc document data whose MDDL
// declares the elements of declared, by namespace.
func MDocElements[M ~map[string]V, V any](declared map[string]M) Shape {
	namespaces := map[string][]string{}
	set := make(map[string]bool, len(declared))
	for namespace, elements := range declared {
		set[namespace] = true
		for element := range elements {
			namespaces[element] = append(namespaces[element], namespace)
		}
	}
	for _, list := range namespaces {
		slices.Sort(list)
	}
	return Shape{kind: mdocElementsShape, namespaces: namespaces, declared: set}
}

// Equal reports whether two shapes hold claims the same way.
func (s Shape) Equal(t Shape) bool {
	return s.kind == t.kind &&
		maps.EqualFunc(s.namespaces, t.namespaces, slices.Equal[[]string]) &&
		maps.Equal(s.declared, t.declared)
}

// Locate returns where the claim p names sits in a claims map of the
// shape, as a pointer through its objects and arrays.
//
// An MDocElements pointer starts with [namespace, element] for an element
// the MDDL declares in that namespace, and continues into the element's
// value. A pointer that starts with a key the MDDL declares neither as a
// namespace nor as an element addresses a document key outside the MDDL:
// an intermediate claim a derivation reads or writes.
func (s Shape) Locate(p Pointer) (Pointer, error) {
	if _, err := p.Components(); err != nil {
		return Pointer{}, err
	}
	switch s.kind {
	case nestedShape:
		return p, nil
	case mdocQualifiedShape:
		namespace, element, err := p.MDoc()
		if err != nil {
			return Pointer{}, err
		}
		return Keys(namespace + "." + element), nil
	case mdocElementsShape:
		return s.locateElement(p)
	}
	return Pointer{}, errors.New("claimpath: the shape is unset")
}

func (s Shape) locateElement(p Pointer) (Pointer, error) {
	first, ok := p.FirstKey()
	if !ok {
		return Pointer{}, fmt.Errorf("claimpath: %s starts with no key of mdoc document data", p)
	}
	if s.declared[first] {
		var element string
		if p.Len() > 1 {
			element, ok = p.components[1].KeyName()
		}
		if !ok || !slices.Contains(s.namespaces[element], first) {
			return Pointer{}, fmt.Errorf("claimpath: %s names no element the MDDL declares in namespace %q", p, first)
		}
		return Pointer{components: p.components[1:]}, nil
	}
	if declaring := s.namespaces[first]; len(declaring) > 0 {
		return Pointer{}, fmt.Errorf("claimpath: the MDDL declares %q in %s; name it [namespace, element]", first, strings.Join(declaring, " and "))
	}
	return p, nil
}

// LocateOne is Locate for a pointer that names one claim: it refuses a
// pointer with null.
func (s Shape) LocateOne(p Pointer) (Pointer, error) {
	location, err := s.Locate(p)
	if err != nil {
		return Pointer{}, err
	}
	if !p.SelectsOne() {
		return Pointer{}, fmt.Errorf("claimpath: %s selects every element of an array where one claim is named", p)
	}
	return location, nil
}

// Key returns the pointer of the top-level document key name: [namespace,
// name] for an element an MDocElements MDDL declares, in the first
// declaring namespace in sorted order, and [name] otherwise. Every
// declaring namespace locates the same key.
func (s Shape) Key(name string) (Pointer, error) {
	switch s.kind {
	case nestedShape:
		return Keys(name), nil
	case mdocElementsShape:
		if declaring := s.namespaces[name]; len(declaring) > 0 {
			return Keys(declaring[0], name), nil
		}
		if s.declared[name] {
			return Pointer{}, fmt.Errorf("claimpath: %q is a namespace of the MDDL, so no pointer names the document key", name)
		}
		return Keys(name), nil
	case mdocQualifiedShape:
		return Pointer{}, fmt.Errorf("claimpath: a presented mdoc holds no document key %q", name)
	}
	return Pointer{}, errors.New("claimpath: the shape is unset")
}

// Get returns the one claim p names in claims.
func (s Shape) Get(claims map[string]any, p Pointer) (any, bool, error) {
	location, err := s.LocateOne(p)
	if err != nil {
		return nil, false, err
	}
	return location.get(claims)
}

// Set writes value at the claim p names in claims.
func (s Shape) Set(claims map[string]any, p Pointer, value any) error {
	location, err := s.LocateOne(p)
	if err != nil {
		return err
	}
	return location.set(claims, value, false)
}

// SetReplacing is Set where a key replaces a null, a scalar or an array
// it passes through with a new object. An index still needs an element
// of an array.
func (s Shape) SetReplacing(claims map[string]any, p Pointer, value any) error {
	location, err := s.LocateOne(p)
	if err != nil {
		return err
	}
	return location.set(claims, value, true)
}

// Delete removes the one claim p names from claims. An absent claim is
// left absent.
func (s Shape) Delete(claims map[string]any, p Pointer) error {
	location, err := s.LocateOne(p)
	if err != nil {
		return err
	}
	return location.delete(claims)
}

// Select returns every claim p selects in claims (see Pointer.Select).
func (s Shape) Select(claims map[string]any, p Pointer) ([]any, error) {
	location, err := s.Locate(p)
	if err != nil {
		return nil, err
	}
	return location.Select(claims)
}
