package openid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// FormatCircuitZk is the DCQL format identifier for a zero-knowledge
// circuit presentation, as profiled by the EUDI nym_auth rulebook.
//
// Distinct from FormatMsoMdocZk, which is multipaz's ZK presentation of an
// mdoc: that one returns a DeviceResponse-shaped vp_token and discloses
// attributes. A circuit_zk query discloses nothing. Every value a Verifier
// wants is the OUTPUT of a function it asks for in Req, computed inside
// the circuit and returned under a handle.
const FormatCircuitZk = "circuit_zk"

// IsCircuitZkFormat reports whether format is the circuit_zk identifier.
func IsCircuitZkFormat(format string) bool { return format == FormatCircuitZk }

// Function identifiers the nym_auth rulebook registers. They are not an
// enumeration this package enforces - a Verifier may ask for a function
// this build has never heard of, and the Wallet decides whether it can.
const (
	// FunctionPseudonym derives a pseudonym from a seed commitment's
	// opening. Rulebook section "Pseudonym generation function".
	FunctionPseudonym = "pseudonym-v1-sha256"
	// FunctionAgeCheck proves a date predicate over birth_date.
	FunctionAgeCheck = "age_check"
)

// ReqItem is one requested calculation inside a circuit_zk credential
// query: a function, a handle its result is returned under, and the
// function's parameters.
//
// Params is an open map and is serialised exactly as given. Nothing here
// coerces a value, drops an empty one, or repairs a malformed one, and
// that is deliberate twice over. The rulebook and the OpenID4VP and DC API
// specifications under it are all still moving, and several generations of
// wallet will be in the field at once - so a Verifier has to be able to
// send a shape this build has never been taught. And this Verifier is the
// tool we test wallets WITH: a builder that quietly fixed a bad request
// could not produce the bad requests a negative test needs.
type ReqItem struct {
	// ID is the function identifier, "id" on the wire. Named ID rather
	// than Function to match the wire member, since the wire is what an
	// operator configures and reads back.
	ID string `json:"id" yaml:"id"`

	// Return is the handle the result is keyed by in the response's
	// results map. The rulebook requires it to be unique within the
	// credential query; nothing here enforces that, because a duplicate
	// is a thing a wallet should be tested against.
	Return string `json:"return" yaml:"return"`

	// Params are the function's parameters, passed through unchanged.
	Params map[string]any `json:"params,omitempty" yaml:"params,omitempty"`

	// Extra carries members this build does not know about, flattened
	// alongside the three above rather than nested. It is how a request
	// shape that arrives after this code was written can still be sent.
	Extra map[string]any `json:"-" yaml:"-"`
}

// MarshalJSON flattens Extra alongside the known members.
func (r ReqItem) MarshalJSON() ([]byte, error) {
	type plain ReqItem // no methods, so no recursion
	return marshalWithExtra(plain(r), r.Extra, "req item")
}

// UnmarshalJSON collects unknown members into Extra.
func (r *ReqItem) UnmarshalJSON(data []byte) error {
	type plain ReqItem
	var known plain
	if err := decodeExact(data, &known); err != nil {
		return err
	}
	*r = ReqItem(known)
	extra, err := unknownMembers(data, "id", "return", "params")
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

// CircuitZkFormat is the circuit_zk entry of client_metadata's
// vp_formats_supported: which proof systems and circuits the Verifier will
// accept a proof from.
//
// Entirely an open map, with the two known arrays as a convenience. The
// rulebook's own example wraps the same information in a
// {"fn_id":..., "input": base64(json)} envelope, and the matcher accepts
// both - so an operator talking to a wallet generation that wants the
// envelope has to be able to send it without waiting for a release here.
type CircuitZkFormat struct {
	// CircuitProofSystemValues lists acceptable proof systems.
	CircuitProofSystemValues []string `json:"circuit_proof_system_values,omitempty" yaml:"circuit_proof_system_values,omitempty" doc_example:"[\"longfellow-libzk-v1\"]"`

	// CircuitIDValues lists acceptable circuit identifiers, from the
	// circuit catalog.
	CircuitIDValues []string `json:"circuit_id_values,omitempty" yaml:"circuit_id_values,omitempty" doc_example:"[\"urn:circuits:longfellow:nym_auth:v1\"]"`

	// Extra carries any other member, flattened alongside the two above -
	// including the envelope form's fn_id and input.
	Extra map[string]any `json:"-" yaml:"-"`
}

// MarshalJSON flattens Extra alongside the known members.
func (c CircuitZkFormat) MarshalJSON() ([]byte, error) {
	type plain CircuitZkFormat
	return marshalWithExtra(plain(c), c.Extra, "circuit_zk client metadata")
}

// UnmarshalJSON collects unknown members into Extra.
func (c *CircuitZkFormat) UnmarshalJSON(data []byte) error {
	type plain CircuitZkFormat
	var known plain
	if err := decodeExact(data, &known); err != nil {
		return err
	}
	*c = CircuitZkFormat(known)
	extra, err := unknownMembers(data, "circuit_proof_system_values", "circuit_id_values")
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

// marshalWithExtra serialises known and merges extra at the top level.
//
// A member in extra that collides with one the struct models is an error
// rather than a silent winner. The check is against every member the type
// DECLARES, not against the ones that happened to survive omitempty: a
// typed field left empty is omitted from the encoding, so checking the
// output would let extra supply a modelled key whenever its field is
// unset - quietly, and only sometimes, which is the worst shape a rule
// can have. Changing the type of a modelled member is what Raw is for.
func marshalWithExtra(known any, extra map[string]any, what string) ([]byte, error) {
	encoded, err := json.Marshal(known)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return encoded, nil
	}

	reserved := declaredJSONKeys(reflect.TypeOf(known))

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &merged); err != nil {
		return nil, err
	}
	for _, key := range slices.Sorted(maps.Keys(extra)) {
		if reserved[key] {
			return nil, fmt.Errorf("%s: %q is a member this type models, so it cannot be set through extra; use raw to change its type", what, key)
		}
		if _, taken := merged[key]; taken {
			return nil, fmt.Errorf("%s: %q is set both as a known member and in extra", what, key)
		}
		value, err := json.Marshal(extra[key])
		if err != nil {
			return nil, fmt.Errorf("%s: extra member %q: %w", what, key, err)
		}
		merged[key] = value
	}
	return json.Marshal(merged)
}

// declaredJSONKeys returns every JSON member name a struct type declares,
// including ones omitempty may drop and ones tagged "-".
//
// Derived from the type rather than listed by hand. A list would be
// correct until the next field is added, and the failure it produces then
// is an extension silently overriding a modelled member.
func declaredJSONKeys(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	keys := map[string]bool{}
	if t.Kind() != reflect.Struct {
		return keys
	}
	for _, field := range reflect.VisibleFields(t) {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		switch name {
		case "", "-":
			// "-" is a field deliberately kept off the wire (Extra, Raw);
			// an empty tag means the field name is the member name.
			if name == "" && field.IsExported() {
				keys[field.Name] = true
			}
			continue
		}
		keys[name] = true
	}
	return keys
}

// decodeExact decodes data into v preserving numbers exactly.
//
// Plain Unmarshal turns every JSON number reaching an `any` into a
// float64, so 9007199254740993 is re-emitted as ...992. These structures
// are mostly `any` by design - a function's params are passed through
// untouched - so without this the one guarantee this package makes about
// params would be false for any integer past 2^53.
func decodeExact(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(v)
}

// unknownMembers returns every top-level member of data that is not named
// in known, so a shape this build does not understand survives a decode
// and can be written back out unchanged.
func unknownMembers(data []byte, known ...string) (map[string]any, error) {
	var all map[string]any
	if err := decodeExact(data, &all); err != nil {
		return nil, err
	}
	for _, name := range known {
		delete(all, name)
	}
	if len(all) == 0 {
		return nil, nil
	}
	return all, nil
}

// YAML support for the extension bags.
//
// Extra is tagged yaml:"-", so without these an operator configuring
// .verifier.preferred_vp_formats.circuit_zk or a presentation request
// template could not use it at all - the members would be read and
// silently dropped, which is the worst way for an escape hatch to fail.
// pkg/configuration loads both of those from YAML.
//
// Known members are decoded into a methodless alias, so yaml.v2 applies
// the struct tags and reports a wrong type itself. Unknown members are
// collected separately and normalised. Nothing goes through JSON on the
// way, which matters: yaml.v2 materialises every nested mapping as
// map[any]any, and what encoding/json does with that has changed between
// releases - it currently coerces an integer key to a string and drops a
// sequence key silently, neither of which should be how a verifier's
// configuration is interpreted.

// MarshalYAML flattens Extra alongside the known members.
func (r ReqItem) MarshalYAML() (any, error) {
	m := map[string]any{"id": r.ID, "return": r.Return}
	if r.Params != nil {
		m["params"] = r.Params
	}
	return mergeExtraYAML(m, r.Extra, declaredJSONKeys(reflect.TypeOf(ReqItem{})), "req item")
}

// UnmarshalYAML captures every member other than the modelled ones.
func (r *ReqItem) UnmarshalYAML(unmarshal func(any) error) error {
	type plain ReqItem // no methods, so yaml.v2 uses the struct tags
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("req item: %w", err)
	}
	*r = ReqItem(known)

	extra, err := yamlExtra(unmarshal, "req item", "id", "return", "params")
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

// MarshalYAML flattens Extra alongside the known members.
func (c CircuitZkFormat) MarshalYAML() (any, error) {
	m := map[string]any{}
	if c.CircuitProofSystemValues != nil {
		m["circuit_proof_system_values"] = c.CircuitProofSystemValues
	}
	if c.CircuitIDValues != nil {
		m["circuit_id_values"] = c.CircuitIDValues
	}
	return mergeExtraYAML(m, c.Extra, declaredJSONKeys(reflect.TypeOf(CircuitZkFormat{})), "circuit_zk client metadata")
}

// UnmarshalYAML captures every member other than the modelled ones -
// including the rulebook example's fn_id and input, which is the shape an
// operator is most likely to need and the one this could not express.
func (c *CircuitZkFormat) UnmarshalYAML(unmarshal func(any) error) error {
	type plain CircuitZkFormat
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("circuit_zk client metadata: %w", err)
	}
	*c = CircuitZkFormat(known)

	extra, err := yamlExtra(unmarshal, "circuit_zk client metadata",
		"circuit_proof_system_values", "circuit_id_values")
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

// yamlExtra decodes the same node a second time as a mapping and returns
// every member not named in known, normalised.
func yamlExtra(unmarshal func(any) error, what string, known ...string) (map[string]any, error) {
	var all map[string]any
	if err := unmarshal(&all); err != nil {
		// Not a mapping at all; the typed decode above has already
		// reported whatever is wrong with it.
		return nil, nil
	}
	for _, name := range known {
		delete(all, name)
	}
	if len(all) == 0 {
		return nil, nil
	}
	normalised, err := normaliseYAML(all, what)
	if err != nil {
		return nil, err
	}
	return normalised.(map[string]any), nil
}

// normaliseYAML converts yaml.v2's map[any]any into map[string]any, all
// the way down, refusing a key that is not a string.
//
// Refusing rather than rendering: a non-string key has no JSON spelling,
// and the alternatives are both silent - encoding/json coerces an integer
// key and drops a sequence key entirely. A verifier that quietly discards
// part of its own configuration is worse than one that will not start.
func normaliseYAML(value any, what string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			converted, err := normaliseYAML(v, what)
			if err != nil {
				return nil, err
			}
			out[k] = converted
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %v is not a string key, and has no JSON spelling", what, k)
			}
			converted, err := normaliseYAML(v, what)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			converted, err := normaliseYAML(v, what)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	default:
		return value, nil
	}
}

// mergeExtraYAML adds extra to m, refusing a member the type models.
//
// Against the DECLARED set, not against what m happens to hold. Checking
// m would only catch the collision when the field was populated, so an
// empty one would let extra take the member over - quietly, and only
// sometimes. That is the same mistake the JSON side had, found in review;
// it was reproduced here within the hour, writing this function, which is
// why both now go through declaredJSONKeys instead of inspecting output.
func mergeExtraYAML(m map[string]any, extra map[string]any, reserved map[string]bool, what string) (any, error) {
	for _, key := range slices.Sorted(maps.Keys(extra)) {
		if reserved[key] {
			return nil, fmt.Errorf("%s: %q is a member this type models, so it cannot be set through extra; use raw to change its type", what, key)
		}
		m[key] = extra[key]
	}
	return m, nil
}
