package claimpath

import (
	"fmt"
	"reflect"
)

// Ref names a claim by a claims path pointer. A Ref the configuration
// loader upgraded from an earlier release's dotted claim name carries
// that name. The earlier release looked the name up as one top-level key
// before the claim it split the name into, and a reader of the Ref does
// the same.
//
// In YAML, a Ref is a pointer, or the mapping {dotted: <name>, path:
// <pointer>} the loader writes.
type Ref struct {
	// Path is the claim.
	Path Pointer
	// dotted is the earlier release's name. It is empty for a Ref written
	// as a pointer.
	dotted string
}

// Dotted returns the earlier release's name a Ref carries.
func (r Ref) Dotted() (string, bool) { return r.dotted, r.dotted != "" }

// Literal returns the value claims holds under the top-level key the
// Ref's dotted name spells. A reader takes it before the claim at Path.
func (r Ref) Literal(claims map[string]any) (any, bool) {
	if r.dotted == "" {
		return nil, false
	}
	value, ok := claims[r.dotted]
	return value, ok
}

// Get returns the claim the Ref names in claims, held in shape: the
// top-level key of its dotted name when claims hold it, and the claim at
// its pointer otherwise.
func (r Ref) Get(shape Shape, claims map[string]any) (any, bool, error) {
	if value, ok := r.Literal(claims); ok {
		return value, true, nil
	}
	return shape.Get(claims, r.Path)
}

// IsZero reports whether the Ref is unset.
func (r Ref) IsZero() bool { return r.Path.IsZero() }

// String renders the pointer.
func (r Ref) String() string { return r.Path.String() }

// upgradedRef is the YAML mapping of a Ref that carries a dotted name.
type upgradedRef struct {
	Dotted string  `yaml:"dotted"`
	Path   Pointer `yaml:"path"`
}

// MarshalYAML writes the pointer, or the mapping of a Ref that carries a
// dotted name.
func (r Ref) MarshalYAML() (any, error) {
	if r.dotted == "" {
		return r.Path.MarshalYAML()
	}
	if _, err := r.Path.Components(); err != nil {
		return nil, err
	}
	return upgradedRef{Dotted: r.dotted, Path: r.Path}, nil
}

// UnmarshalYAML reads a pointer, or the mapping {dotted: <name>, path:
// <pointer>} with a non-empty name and a pointer. YAML null leaves the
// Ref unset.
func (r *Ref) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	fields, ok := raw.(map[any]any)
	if !ok {
		var path Pointer
		if err := unmarshal(&path); err != nil {
			return err
		}
		*r = Ref{Path: path}
		return nil
	}
	if len(fields) != 2 || fields["dotted"] == nil || fields["path"] == nil {
		return fmt.Errorf("%w: a claim is a claims path pointer, or the mapping {dotted, path} of an upgraded dotted name", ErrMalformed)
	}
	var upgraded upgradedRef
	if err := unmarshal(&upgraded); err != nil {
		return err
	}
	if upgraded.Dotted == "" || upgraded.Path.IsZero() {
		return fmt.Errorf("%w: an upgraded dotted name has a non-empty name and a claims path pointer", ErrMalformed)
	}
	*r = Ref{Path: upgraded.Path, dotted: upgraded.Dotted}
	return nil
}

// refValidationValue is ValidationValue of a Ref's pointer.
func refValidationValue(field reflect.Value) any {
	r, ok := field.Interface().(Ref)
	if !ok {
		return nil
	}
	return ValidationValue(reflect.ValueOf(r.Path))
}
