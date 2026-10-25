package primitives

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
)

// Adding a primitive: add an Args struct + Apply method in a file in this
// package (e.g. age.go), then add a pointer field to Derivation below with a
// `yaml:"..."` tag. No changes needed in the dispatcher, validator, or docs
// generator. Derivation is the single source of truth: gen_config_docs walks
// these fields, and the derivation_entry struct-level validator (registered
// in pkg/helpers) enforces the exactly-one-field rule. A primitive reads the
// claim at its claimpath.Pointer field Input and writes the claim at its
// field Output, which defaults to Input; the loader resolves both by these
// names.

// Derivation is one post-verification claim computation configured on a scope; exactly one field must be set and that field's Apply method runs.
//
// Each list entry under a scope's `derivations` field is keyed by primitive name (e.g. `age_over_thresholds:` or `lowercase: { input: [email] }`). The subsections below catalog the primitives and their parameters.
//
// Every claim a primitive reads or writes is a claims path pointer (OpenID4VP 1.0 section 7). An output is a claim of the issued credential's document. An input is a claim of the source data - the presented credential for a presentation source, the document otherwise - and a claim of the issued document when an earlier derivation of the list writes it or a claim above it. A dotted string is read the same way: an mdoc output names the element its MDDL declares, or a document key it does not declare.
type Derivation struct {
	// AgeOverThresholds emits two boolean claims per configured threshold
	// N from an ISO YYYY-MM-DD birthdate: age_over_N (completed years at
	// `now`) and over_N_this_year (reaches N at some point in `now`'s
	// calendar year).
	AgeOverThresholds *AgeOverThresholdsArgs `yaml:"age_over_thresholds,omitempty"`

	// Lowercase applies strings.ToLower elementwise.
	Lowercase *LowercaseArgs `yaml:"lowercase,omitempty"`

	// Uppercase applies strings.ToUpper elementwise.
	Uppercase *UppercaseArgs `yaml:"uppercase,omitempty"`

	// Trim applies strings.TrimSpace elementwise.
	Trim *TrimArgs `yaml:"trim,omitempty"`

	// CountryAlpha2 maps country names or alpha-3 codes to ISO 3166-1
	// alpha-2 codes elementwise. Unknown inputs pass through unchanged.
	CountryAlpha2 *CountryAlpha2Args `yaml:"country_alpha2,omitempty"`

	// CountryAlpha3 maps country names or alpha-2 codes to ISO 3166-1
	// alpha-3 codes elementwise. Unknown inputs pass through unchanged.
	CountryAlpha3 *CountryAlpha3Args `yaml:"country_alpha3,omitempty"`

	// YYYYMMDDToISO converts a SCHAC schacDateOfBirth ("YYYYMMDD") claim to
	// ISO full-date ("YYYY-MM-DD"). Impossible calendar dates are an error.
	YYYYMMDDToISO *YYYYMMDDToISOArgs `yaml:"yyyymmdd_to_iso,omitempty"`

	// SWAMIDHighestAssuranceLevel reduces a multi-valued eduPersonAssurance
	// claim to the strongest recognised SWAMID Assurance Framework URI.
	SWAMIDHighestAssuranceLevel *SWAMIDHighestAssuranceLevelArgs `yaml:"swamid_highest_assurance_level,omitempty"`

	// Random writes a freshly generated random value to a claim the source
	// data did not supply - a document identifier, typically. The only
	// primitive here that reads nothing and is not a pure function of its
	// input; see RandomArgs for where the value is generated and how long
	// it lives.
	Random *RandomArgs `yaml:"random,omitempty"`
	// Copy writes an input claim's value, of any type, under another
	// claim name.
	Copy *CopyArgs `yaml:"copy,omitempty"`
	// HashCommitment fulfils a to_wallet hash_commitment entry of the
	// credential's auxiliary_data.
	HashCommitment *HashCommitmentArgs `yaml:"hash_commitment,omitempty"`
}

// Applier is the shape every primitive Args struct implements. Every
// pointer field on Derivation must point at a type implementing Applier;
// the reflection-based dispatcher below relies on it.
type Applier interface {
	Apply(claims Claims, now time.Time) ([]Write, error)
}

// Claims is what a derivation reads.
type Claims interface {
	// Input returns the claim at an input pointer: in the issued claims
	// when an earlier derivation of the list writes the pointer or a
	// prefix of it, in the source claims otherwise.
	Input(p claimpath.Pointer) (any, bool, error)
	// Issued returns the claim at a pointer into the issued claims.
	Issued(p claimpath.Pointer) (any, bool, error)
	// Named returns the pointer into the issued claims of a claim a
	// primitive names itself, such as age_over_18.
	Named(name string) (claimpath.Pointer, error)
}

// Write is a value a derivation writes at Path, a pointer into the issued
// claims.
type Write struct {
	Path  claimpath.Pointer
	Value any
}

// Apply runs whichever primitive is configured on d. Returns an error when
// zero or more than one field is set; the struct-level validator catches
// that case at config load time, but Apply stays defensive for callers
// that build a Derivation programmatically (tests, bootstrapping tools).
func (d *Derivation) Apply(claims Claims, now time.Time) ([]Write, error) {
	a, name, err := d.selected()
	if err != nil {
		return nil, err
	}
	out, err := a.Apply(claims, now)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// Input returns the pointer of the claim the configured primitive reads.
func (d *Derivation) Input() (claimpath.Pointer, bool) {
	a, _, err := d.selected()
	if err != nil {
		return claimpath.Pointer{}, false
	}
	input, ok := pointerField(a, "Input")
	if !ok {
		return claimpath.Pointer{}, false
	}
	return *input, true
}

// ownOutputs is a primitive that names the claims it writes itself.
type ownOutputs interface {
	outputs(named func(string) (claimpath.Pointer, error)) ([]claimpath.Pointer, error)
}

// Outputs returns the pointers of the claims the configured primitive
// writes: its Output, or its Input when it writes in place. named returns
// the pointer of a claim a primitive names itself.
func (d *Derivation) Outputs(named func(string) (claimpath.Pointer, error)) ([]claimpath.Pointer, error) {
	a, _, err := d.selected()
	if err != nil {
		return nil, err
	}
	if own, ok := a.(ownOutputs); ok {
		return own.outputs(named)
	}
	output, ok := outputOf(a)
	if !ok {
		return nil, nil
	}
	return []claimpath.Pointer{output}, nil
}

// outputOf returns the claim a primitive writes: its Output, or its Input
// when Output is unset.
func outputOf(a Applier) (claimpath.Pointer, bool) {
	if output, ok := pointerField(a, "Output"); ok && !output.IsZero() {
		return *output, true
	}
	if input, ok := pointerField(a, "Input"); ok {
		return *input, true
	}
	return claimpath.Pointer{}, false
}

// pointerField returns the address of a primitive's claimpath.Pointer field
// name.
func pointerField(a Applier, name string) (*claimpath.Pointer, bool) {
	f := reflect.ValueOf(a).Elem().FieldByName(name)
	if !f.IsValid() || f.Type() != reflect.TypeFor[claimpath.Pointer]() {
		return nil, false
	}
	return f.Addr().Interface().(*claimpath.Pointer), true
}

// ReformatsInput reports whether the configured primitive's output is a
// reformatting of its input claim, and so carries the input's provenance.
// Primitives that compute new values (age booleans, random identifiers)
// return false, as does any primitive not listed here.
func (d *Derivation) ReformatsInput() bool {
	return d.Lowercase != nil || d.Uppercase != nil || d.Trim != nil ||
		d.CountryAlpha2 != nil || d.CountryAlpha3 != nil ||
		d.YYYYMMDDToISO != nil || d.SWAMIDHighestAssuranceLevel != nil ||
		d.Copy != nil
}

// SelectedName returns the YAML key of the configured primitive, or ""
// when zero or many fields are set. Provided for error-context callers.
func (d *Derivation) SelectedName() string {
	_, name, err := d.selected()
	if err != nil {
		return ""
	}
	return name
}

func (d *Derivation) selected() (Applier, string, error) {
	v := reflect.ValueOf(d).Elem()
	t := v.Type()
	var (
		chosen Applier
		name   string
		count  int
	)
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || f.IsNil() {
			continue
		}
		a, ok := f.Interface().(Applier)
		if !ok {
			return nil, "", fmt.Errorf("derivation field %s does not implement Applier", t.Field(i).Name)
		}
		chosen = a
		name = yamlKey(t.Field(i))
		count++
	}
	switch count {
	case 0:
		return nil, "", errors.New("derivation entry sets no primitive")
	case 1:
		return chosen, name, nil
	default:
		return nil, "", errors.New("derivation entry sets more than one primitive")
	}
}

// yamlKey returns the yaml struct tag key (before the first comma), falling
// back to the Go field name.
func yamlKey(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if i := indexByte(tag, ','); i >= 0 {
		return tag[:i]
	}
	if tag != "" {
		return tag
	}
	return f.Name
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// FieldNames returns the YAML names of every primitive field on Derivation
// in declaration order. Used by gen_config_docs to enumerate primitives.
func FieldNames() []string {
	t := reflect.TypeFor[Derivation]()
	out := make([]string, 0, t.NumField())
	for field := range t.Fields() {
		out = append(out, yamlKey(field))
	}
	return out
}
