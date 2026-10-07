package primitives

import (
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Adding a primitive: add an Args struct + Apply method in a file in this
// package (e.g. age.go), then add a pointer field to Derivation below with a
// `yaml:"..."` tag. No changes needed in the dispatcher, validator, or docs
// generator. Derivation is the single source of truth: gen_config_docs walks
// these fields, and the derivation_entry struct-level validator (registered
// in pkg/helpers) enforces the exactly-one-field rule.

// Derivation is one post-verification claim computation configured on a scope; exactly one field must be set and that field's Apply method runs.
//
// Each list entry under a scope's `derivations` field is keyed by primitive name (e.g. `age_over_thresholds:` or `lowercase: { input: email }`). The subsections below catalog the primitives and their parameters.
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
}

// Applier is the shape every primitive Args struct implements. Every
// pointer field on Derivation must point at a type implementing Applier;
// the reflection-based dispatcher below relies on it.
type Applier interface {
	Apply(claims map[string]any, now time.Time) (map[string]any, error)
}

// Apply runs whichever primitive is configured on d. Returns an error when
// zero or more than one field is set; the struct-level validator catches
// that case at config load time, but Apply stays defensive for callers
// that build a Derivation programmatically (tests, bootstrapping tools).
func (d *Derivation) Apply(claims map[string]any, now time.Time) (map[string]any, error) {
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
