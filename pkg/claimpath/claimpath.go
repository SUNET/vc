// Package claimpath implements the claims path pointer of OpenID4VP 1.0
// section 7, the syntax DCQL, type metadata and this configuration use to
// name a claim in a credential.
package claimpath

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Pointer is a claims path pointer: a non-empty sequence of keys, null
// (every element of an array) and array indices. A Lenient decode also
// reads the empty array, which the earlier release accepted as the path of
// a type metadata claim and of an issuer metadata claim; such a pointer
// selects no claim.
type Pointer struct {
	components []Component
	// empty marks the empty array a Lenient decode read.
	empty bool
}

// Component is one element of a Pointer.
type Component struct {
	kind  kind
	key   string
	index uint
}

type kind uint8

const (
	keyKind kind = iota + 1
	allKind
	indexKind
)

// Key selects the claim named key in an object.
func Key(key string) Component { return Component{kind: keyKind, key: key} }

// All selects every element of an array.
func All() Component { return Component{kind: allKind} }

// Index selects the element at index in an array.
func Index(index uint) Component { return Component{kind: indexKind, index: index} }

// KeyName returns the key a component selects.
func (c Component) KeyName() (string, bool) { return c.key, c.kind == keyKind }

// IsAll reports whether the component selects every element of an array.
func (c Component) IsAll() bool { return c.kind == allKind }

// IndexValue returns the array index a component selects.
func (c Component) IndexValue() (uint, bool) { return c.index, c.kind == indexKind }

// New returns the pointer of its components.
func New(first Component, rest ...Component) Pointer {
	return Pointer{components: append([]Component{first}, rest...)}
}

// Keys returns the pointer of its keys.
func Keys(first string, rest ...string) Pointer {
	components := make([]Component, 0, 1+len(rest))
	components = append(components, Key(first))
	for _, key := range rest {
		components = append(components, Key(key))
	}
	return Pointer{components: components}
}

// FromComponents returns the pointer of components. It refuses an empty
// slice.
func FromComponents(components []Component) (Pointer, error) {
	if len(components) == 0 {
		return Pointer{}, errors.New("claimpath: a claims path pointer is a non-empty array")
	}
	return Pointer{components: slices.Clone(components)}, nil
}

// FromKeys returns the pointer of keys. It refuses an empty slice.
func FromKeys(keys []string) (Pointer, error) {
	if len(keys) == 0 {
		return Pointer{}, errors.New("claimpath: a claims path pointer is a non-empty array")
	}
	return Keys(keys[0], keys[1:]...), nil
}

// EmptyArray returns the pointer of the empty array.
func EmptyArray() Pointer { return Pointer{empty: true} }

// IsZero reports whether the pointer is unset.
func (p Pointer) IsZero() bool { return len(p.components) == 0 && !p.empty }

// IsEmptyArray reports whether the pointer is the empty array.
func (p Pointer) IsEmptyArray() bool { return p.empty }

// Components returns a copy of the pointer's components. An unset pointer
// and the empty array are an error.
func (p Pointer) Components() ([]Component, error) {
	if err := p.requireComponents(); err != nil {
		return nil, err
	}
	return slices.Clone(p.components), nil
}

// requireComponents refuses an unset pointer and the empty array.
func (p Pointer) requireComponents() error {
	switch {
	case p.empty:
		return errors.New("claimpath: the claims path pointer is the empty array")
	case len(p.components) == 0:
		return errors.New("claimpath: the claims path pointer is unset")
	}
	return nil
}

// KeyNames returns the keys of a pointer made only of keys.
func (p Pointer) KeyNames() ([]string, bool) {
	if len(p.components) == 0 {
		return nil, false
	}
	keys := make([]string, len(p.components))
	for i, c := range p.components {
		if c.kind != keyKind {
			return nil, false
		}
		keys[i] = c.key
	}
	return keys, true
}

// MDoc returns the namespace and data element identifier of a pointer into
// an ISO mdoc, which is exactly two keys (OpenID4VP 1.0 section 7.2).
func (p Pointer) MDoc() (namespace, element string, err error) {
	keys, ok := p.KeyNames()
	if !ok || len(keys) != 2 {
		return "", "", fmt.Errorf("claimpath: %s is no [namespace, element] pointer into an mdoc", p)
	}
	return keys[0], keys[1], nil
}

// Name returns the key a claim is named by: the last component, which is
// a key.
func (p Pointer) Name() (string, bool) {
	if len(p.components) == 0 {
		return "", false
	}
	return p.components[len(p.components)-1].KeyName()
}

// FirstKey returns the key a pointer starts with.
func (p Pointer) FirstKey() (string, bool) {
	if len(p.components) == 0 {
		return "", false
	}
	return p.components[0].KeyName()
}

// Parent returns the pointer without its last component. A pointer of
// one component has none.
func (p Pointer) Parent() (Pointer, bool) {
	return p.Prefix(len(p.components) - 1)
}

// Last returns the last component of a pointer.
func (p Pointer) Last() (Component, bool) {
	if len(p.components) == 0 {
		return Component{}, false
	}
	return p.components[len(p.components)-1], true
}

// Prefix returns the first n components of the pointer, for n from 1 to
// its length.
func (p Pointer) Prefix(n int) (Pointer, bool) {
	if n < 1 || n > len(p.components) {
		return Pointer{}, false
	}
	return Pointer{components: p.components[:n:n]}, true
}

// Ancestors returns the pointers of the claims that hold p's claim: each
// strict prefix of p, shortest first.
func (p Pointer) Ancestors() []Pointer {
	if len(p.components) < 2 {
		return nil
	}
	out := make([]Pointer, 0, len(p.components)-1)
	for n := 1; n < len(p.components); n++ {
		out = append(out, Pointer{components: p.components[:n:n]})
	}
	return out
}

// KeyPrefix returns the leading keys of the pointer, up to its first null
// or index.
func (p Pointer) KeyPrefix() (Pointer, bool) {
	n := slices.IndexFunc(p.components, func(c Component) bool { return c.kind != keyKind })
	if n < 0 {
		n = len(p.components)
	}
	if n == 0 {
		return Pointer{}, false
	}
	return Pointer{components: p.components[:n:n]}, true
}

// Len returns the number of components of a pointer.
func (p Pointer) Len() int {
	return len(p.components)
}

// Equal reports whether two set pointers are the same.
func (p Pointer) Equal(q Pointer) bool {
	return len(p.components) > 0 && slices.Equal(p.components, q.components)
}

// HasPrefix reports whether prefix is the start of p, or p itself.
func (p Pointer) HasPrefix(prefix Pointer) bool {
	return len(prefix.components) > 0 &&
		len(prefix.components) <= len(p.components) &&
		slices.Equal(p.components[:len(prefix.components)], prefix.components)
}

// SelectsOne reports whether a pointer selects at most one claim: it is
// set and has no null component.
func (p Pointer) SelectsOne() bool {
	return len(p.components) > 0 && !slices.ContainsFunc(p.components, Component.IsAll)
}

// Rebase returns p with its prefix from replaced by to, and whether p
// starts with from.
func (p Pointer) Rebase(from, to Pointer) (Pointer, bool) {
	if !p.HasPrefix(from) {
		return Pointer{}, false
	}
	return to.Append(p.components[len(from.components):]...), true
}

// Map returns the pointer with each component replaced by f's result.
func (p Pointer) Map(f func(Component) Component) Pointer {
	out := Pointer{empty: p.empty}
	if len(p.components) > 0 {
		out.components = make([]Component, len(p.components))
		for i, c := range p.components {
			out.components[i] = f(c)
		}
	}
	return out
}

// Append returns p extended with components.
func (p Pointer) Append(components ...Component) Pointer {
	return Pointer{components: append(slices.Clone(p.components), components...)}
}

// String renders the pointer as an array, such as ["address","locality"].
func (p Pointer) String() string {
	var b strings.Builder
	b.WriteByte('[')
	for i, c := range p.components {
		if i > 0 {
			b.WriteByte(',')
		}
		switch c.kind {
		case keyKind:
			b.WriteString(strconv.Quote(c.key))
		case allKind:
			b.WriteString("null")
		case indexKind:
			b.WriteString(strconv.FormatUint(uint64(c.index), 10))
		}
	}
	b.WriteByte(']')
	return b.String()
}

// values is the pointer as JSON values: string, nil or uint.
func (p Pointer) values() []any {
	out := make([]any, len(p.components))
	for i, c := range p.components {
		switch c.kind {
		case keyKind:
			out[i] = c.key
		case allKind:
			out[i] = nil
		case indexKind:
			out[i] = c.index
		}
	}
	return out
}

// fromValues reads a pointer from decoded JSON, YAML or BSON values.
// ErrMalformed is the error of a value that decodes as no claims path
// pointer. A *StringError is one.
var ErrMalformed = errors.New("claimpath: the value is no claims path pointer")

func fromValues(values []any) (Pointer, error) {
	if len(values) == 0 {
		return Pointer{}, fmt.Errorf("%w: a claims path pointer is a non-empty array", ErrMalformed)
	}
	components := make([]Component, len(values))
	for i, value := range values {
		c, err := component(value)
		if err != nil {
			return Pointer{}, fmt.Errorf("%w: element %d: %w", ErrMalformed, i, err)
		}
		components[i] = c
	}
	return Pointer{components: components}, nil
}

func component(value any) (Component, error) {
	switch v := value.(type) {
	case string:
		return Key(v), nil
	case nil:
		return All(), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return Component{}, fmt.Errorf("%s is no non-negative integer", v)
		}
		return indexOf(n)
	case int:
		return indexOf(int64(v))
	case int32:
		return indexOf(int64(v))
	case int64:
		return indexOf(v)
	case uint64:
		if v > math.MaxInt64 {
			return Component{}, fmt.Errorf("%d exceeds the largest index", v)
		}
		return Index(uint(v)), nil
	case float64:
		if v != math.Trunc(v) || v > math.MaxInt64 {
			return Component{}, fmt.Errorf("%v is no non-negative integer", v)
		}
		return indexOf(int64(v))
	default:
		return Component{}, fmt.Errorf("%v is no string, null or non-negative integer", value)
	}
}

func indexOf(n int64) (Component, error) {
	if n < 0 {
		return Component{}, fmt.Errorf("%d is no non-negative integer", n)
	}
	return Index(uint(n)), nil
}

// MarshalJSON writes the pointer as its JSON array.
func (p Pointer) MarshalJSON() ([]byte, error) {
	if err := p.requireComponents(); err != nil && !p.empty {
		return nil, err
	}
	return json.Marshal(p.values())
}

// UnmarshalJSON reads a JSON array. JSON null leaves the pointer unset.
func (p *Pointer) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		return &StringError{Text: text}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values []any
	if err := decoder.Decode(&values); err != nil {
		return fmt.Errorf("%w: a claims path pointer is a JSON array", ErrMalformed)
	}
	pointer, err := fromValues(values)
	if err != nil {
		return err
	}
	*p = pointer
	return nil
}

// MarshalYAML writes the pointer as a sequence.
func (p Pointer) MarshalYAML() (any, error) {
	if err := p.requireComponents(); err != nil && !p.empty {
		return nil, err
	}
	return p.values(), nil
}

// UnmarshalYAML reads a sequence. YAML null leaves the pointer unset.
func (p *Pointer) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return &StringError{Text: v}
	case []any:
		pointer, err := fromValues(v)
		if err != nil {
			return err
		}
		*p = pointer
		return nil
	default:
		return fmt.Errorf("%w: a claims path pointer is an array; %v is a %T", ErrMalformed, raw, raw)
	}
}

// Lenient decodes a claims path pointer from JSON, and reads the empty
// array as EmptyArray.
type Lenient struct {
	Pointer
}

// UnmarshalJSON reads a JSON array as Pointer.UnmarshalJSON does, and the
// empty array as EmptyArray. Null leaves the pointer unset, as it leaves a
// Go slice nil, so of two members "path" the later one decides.
func (l *Lenient) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err == nil && len(values) == 0 {
		if values == nil {
			l.Pointer = Pointer{}
		} else {
			l.Pointer = EmptyArray()
		}
		return nil
	}
	return l.Pointer.UnmarshalJSON(data)
}

// StringError is a claims path pointer written as a string.
type StringError struct {
	// Text is the string.
	Text string
}

// Unwrap returns ErrMalformed.
func (e *StringError) Unwrap() error { return ErrMalformed }

// Error suggests the array of the string split at each dot.
func (e *StringError) Error() string {
	parts := strings.Split(e.Text, ".")
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = strconv.Quote(part)
	}
	return fmt.Sprintf("claims path pointer %q is a string; write it as an array, such as [%s] (OpenID4VP 1.0 §7)", e.Text, strings.Join(quoted, ", "))
}

// ValidationValue is the value go-playground/validator checks for a
// Pointer: the slice of its components, which is nil for an unset pointer
// and empty for the empty array. A validator that registers it with
// RegisterCustomTypeFunc reads "required" as a pointer other than unset,
// and "min=1" as a pointer with a component.
func ValidationValue(field reflect.Value) any {
	p, ok := field.Interface().(Pointer)
	if !ok {
		return nil
	}
	if p.empty {
		return []Component{}
	}
	return p.components
}

// NonEmptyKeysTag is the validation tag of a pointer whose keys are each a
// non-empty string.
const NonEmptyKeysTag = "nonempty_keys"

// RegisterValidation registers ValidationValue and NonEmptyKeysTag with
// v. A Ref validates as its pointer.
func RegisterValidation(v *validator.Validate) error {
	v.RegisterCustomTypeFunc(ValidationValue, Pointer{})
	v.RegisterCustomTypeFunc(refValidationValue, Ref{})
	return v.RegisterValidation(NonEmptyKeysTag, nonEmptyKeys)
}

// nonEmptyKeys reports whether a pointer, as ValidationValue gives it, has
// no empty key.
func nonEmptyKeys(fl validator.FieldLevel) bool {
	components, ok := fl.Field().Interface().([]Component)
	return ok && !slices.ContainsFunc(components, func(c Component) bool { return c.kind == keyKind && c.key == "" })
}

// Compare orders pointers by their rendering, for a stable order.
func Compare(p, q Pointer) int {
	return strings.Compare(p.String(), q.String())
}
