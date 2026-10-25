package claimpath

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

var pointerType = reflect.TypeFor[Pointer]()

// CheckResolved walks every field a YAML document can set under root, and
// returns a PendingError for the first pointer still pending. The loader
// resolves each dotted claim it knows how to read, so a pointer left
// pending is in a field that takes an array.
func CheckResolved(root any) error {
	w := walker{visited: map[uintptr]bool{}}
	return w.walk(reflect.ValueOf(root), "")
}

type walker struct {
	visited map[uintptr]bool
}

func (w walker) walk(v reflect.Value, at string) error {
	if !v.IsValid() {
		return nil
	}
	if v.Type() == pointerType {
		return pendingAt(v.Interface().(Pointer), at)
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || w.visited[v.Pointer()] {
			return nil
		}
		w.visited[v.Pointer()] = true
		return w.walk(v.Elem(), at)
	case reflect.Interface:
		return w.walk(v.Elem(), at)
	case reflect.Struct:
		return w.walkStruct(v, at)
	case reflect.Slice, reflect.Array:
		return w.walkSlice(v, at)
	case reflect.Map:
		return w.walkMap(v, at)
	}
	return nil
}

func (w walker) walkStruct(v reflect.Value, at string) error {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		name, ok := yamlName(field)
		if !ok {
			continue
		}
		if err := w.walk(v.Field(i), join(at, name)); err != nil {
			return err
		}
	}
	return nil
}

func (w walker) walkSlice(v reflect.Value, at string) error {
	if !mayHold(v.Type().Elem()) {
		return nil
	}
	for i := range v.Len() {
		if err := w.walk(v.Index(i), fmt.Sprintf("%s[%d]", at, i)); err != nil {
			return err
		}
	}
	return nil
}

func (w walker) walkMap(v reflect.Value, at string) error {
	if !mayHold(v.Type().Elem()) {
		return nil
	}
	keys := v.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int {
		return strings.Compare(fmt.Sprint(a.Interface()), fmt.Sprint(b.Interface()))
	})
	for _, key := range keys {
		if err := w.walk(v.MapIndex(key), join(at, fmt.Sprint(key.Interface()))); err != nil {
			return err
		}
	}
	return nil
}

// mayHold reports whether a value of type t can hold a Pointer.
func mayHold(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct, reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Array, reflect.Map:
		return true
	}
	return false
}

// yamlName returns the name YAML gives a field: "" for an inlined one,
// and false for one YAML does not set.
func yamlName(field reflect.StructField) (string, bool) {
	if !field.IsExported() {
		return "", false
	}
	tag := field.Tag.Get("yaml")
	name, options, _ := strings.Cut(tag, ",")
	switch {
	case name == "-":
		return "", false
	case slices.Contains(strings.Split(options, ","), "inline"):
		return "", true
	case name == "":
		return strings.ToLower(field.Name), true
	}
	return name, true
}

func join(at, name string) string {
	switch {
	case name == "":
		return at
	case at == "":
		return name
	}
	return at + "." + name
}

// PendingError is a pointer CheckResolved found pending.
type PendingError struct {
	// At is where the pointer is, by YAML names.
	At string
	// Dotted is the pointer's dotted string.
	Dotted string
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("%s: the dotted claim %q is in a field that takes a claims path pointer array", e.At, e.Dotted)
}

func pendingAt(p Pointer, at string) error {
	if dotted, pending := p.Pending(); pending {
		return &PendingError{At: at, Dotted: dotted}
	}
	return nil
}
