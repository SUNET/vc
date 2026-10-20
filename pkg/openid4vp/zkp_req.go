package openid4vp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	yamlv2 "gopkg.in/yaml.v2"
)

// FormatZkpReq is the DCQL format identifier for a zero-knowledge
// circuit presentation, as profiled by the EUDI nym_auth rulebook.
//
// Distinct from FormatMsoMdocZk, which is multipaz's ZK presentation of an
// mdoc: that one returns a DeviceResponse-shaped vp_token and discloses
// attributes. A circuit_zk query discloses nothing. Every value a Verifier
// wants is the OUTPUT of a function it asks for in Req, computed inside
// the circuit and returned under a handle.
const FormatZkpReq = "zkp_req"

// IsZkpReqFormat reports whether format is the circuit_zk identifier.
func IsZkpReqFormat(format string) bool { return format == FormatZkpReq }

// Function identifiers the nym_auth rulebook registers. They are not an
// enumeration this package enforces - a Verifier may ask for a function
// this build has never heard of, and the Wallet decides whether it can.
const (
	// FunctionPseudonym derives a pseudonym from a seed commitment's
	// opening. Rulebook section "Pseudonym generation function".
	FunctionPseudonym = "pseudonym"
	// FunctionAgeCheck proves a date predicate over birth_date.
	FunctionAgeCheck = "age_check"
)

// The stored attestation a zkp_req proof is made over.
//
// mso_mdoc is the ISO/IEC 18013-5 mdoc and is what the default
// profile stores. bbs_cd is defined and held: its presentations
// validate by the same rules, and nothing more is claimed for it.
const (
	SourceFormatMsoMdoc = "mso_mdoc"
	SourceFormatBbsCd   = "bbs_cd"
)

// The pseudonym functions' `prf` parameter, which fixes the width of
// the pseudonym a result carries.
//
// The width is the prf's, not the function's: a pseudonym with no
// agreed width is one this verifier cannot check, so an item naming
// no known prf is refused rather than measured against a guess.
const (
	// PseudonymVer1 is the only pseudonym `ver` v0.4 defines. The
	// parameter is REQUIRED, so there is no "unversioned" request.
	PseudonymVer1 = 1

	PrfSHA256           = "sha-256"
	PrfHashDHBLS12381G1 = "hashdh-bls12381g1"
)

// ReqItem is one requested calculation inside a circuit_zk credential
// query: a function, a handle its result is returned under, and the
// function's parameters.
//
// A zkp_req preset needs two things to be published - a non-empty _req,
// and verifier.preferred_vp_formats.zkp_req advertising the format:
//
//	```yaml
//	verifier:
//	  preferred_vp_formats:
//	    zkp_req: {}              # or a circuit filter
//	  presets:
//	    "Pseudonym":
//	      credentials:
//	        nym_auth:
//	          format: zkp_req
//	          validate: nym_auth     # optional
//	          # `req` is the PRESET key; the wire member it becomes is
//	          # `_req`. They differ on purpose - the preset is this
//	          # repository's configuration surface, not the wire.
//	          req:
//	            - fn_id: pseudonym
//	              return: nym-123
//	              params:
//	                config: known-offender-matching-ssc
//	                ver: 1
//	                prf: sha-256
//	```
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
	// FnID is the function identifier, "fn_id" on the wire. Named for
	// the wire member rather than Function, since the wire is what an
	// operator configures and reads back.
	FnID string `json:"fn_id" yaml:"fn_id"`

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
	return marshalWithExtra(plain(r), r.Extra, "_req item")
}

// UnmarshalJSON collects unknown members into Extra.
func (r *ReqItem) UnmarshalJSON(data []byte) error {
	knownObject, extra, err := splitMembers(data, "_req item", "fn_id", "return", "params")
	if err != nil {
		return err
	}
	type plain ReqItem
	var known plain
	if err := decodeExact(knownObject, &known); err != nil {
		return err
	}
	*r = ReqItem(known)
	r.Extra = extra
	return nil
}

// ZkpReqFormat is the circuit_zk entry of client_metadata's
// vp_formats_supported: which proof systems and circuits the Verifier will
// accept a proof from.
//
// Entirely an open map, with the two known arrays as a convenience. The
// rulebook's own example wraps the same information in a
// {"fn_id":..., "input": base64(json)} envelope, and the matcher accepts
// both - so an operator talking to a wallet generation that wants the
// envelope has to be able to send it without waiting for a release here.
type ZkpReqFormat struct {
	// omitzero, not omitempty, on both arrays below.
	//
	// The matcher's contract distinguishes an EMPTY list - a filter that
	// nothing matches - from an ABSENT one, which is no filter at all.
	// omitempty cannot tell them apart, so an explicit
	// {"system_id_values": []} was serialised as {} and the constraint
	// silently disappeared: the wallet saw an unfiltered request where
	// the operator had asked for one that matches nothing.
	//
	// omitzero omits only the zero value, which for a slice is nil, so
	// absent stays absent and empty survives. MarshalYAML below already
	// made this distinction by hand (it tests != nil), so only the JSON
	// path was losing it.

	// ProofSystemValues lists acceptable proof systems.
	ProofSystemValues []string `json:"proof_system_values,omitzero" yaml:"proof_system_values,omitempty" doc_example:"[\"longfellow-libzk-v1\"]"`

	// SystemIDValues lists acceptable circuit identifiers, from the
	// circuit catalog.
	SystemIDValues []string `json:"system_id_values,omitzero" yaml:"system_id_values,omitempty" doc_example:"[\"urn:circuits:longfellow:nym_auth:v1\"]"`

	// Extra carries any other member, flattened alongside the two above -
	// including the envelope form's fn_id and input.
	Extra map[string]any `json:"-" yaml:"-"`
}

// MarshalJSON flattens Extra alongside the known members.
func (c ZkpReqFormat) MarshalJSON() ([]byte, error) {
	type plain ZkpReqFormat
	return marshalWithExtra(plain(c), c.Extra, "zkp_req client metadata")
}

// nullFilterError reports a modelled filter array this type cannot hold.
//
// Neither spelling survives the round trip. A null ARRAY decodes to a nil
// slice, which omitzero then omits, so an explicitly supplied filter
// becomes NO filter and the wallet sees an unfiltered request. A null
// ELEMENT decodes to the zero string, so a filter naming nothing becomes
// one naming the empty string. The model has nowhere to keep the
// difference, so this refuses rather than repairs - as the duplicate and
// overflow checks beside it do, and for the same reason: a changed
// request that looks perfectly well formed is the worst thing this
// serialiser can emit.
func nullFilterError(what, name string, index int) error {
	if index < 0 {
		return fmt.Errorf("%s: %q is null, which cannot be told from an absent member once decoded; "+
			"omit it for no filter at all, or give [] for a filter that matches nothing", what, name)
	}
	return fmt.Errorf("%s: %q[%d] is null, which would be read back as an empty string; "+
		"remove the element, or write the value you mean", what, name, index)
}

// refuseNullFiltersJSON refuses a null modelled array, or one holding a
// null element, in JSON.
func refuseNullFiltersJSON(data []byte, what string, names ...string) error {
	var members map[string]json.RawMessage
	if err := decodeExact(data, &members); err != nil {
		return nil // not an object; the typed decode reports it
	}
	for _, name := range names {
		raw, present := members[name]
		if !present {
			continue
		}
		if string(bytes.TrimSpace(raw)) == "null" {
			return nullFilterError(what, name, -1)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			continue // wrong kind; the typed decode reports it
		}
		for i, item := range items {
			if string(bytes.TrimSpace(item)) == "null" {
				return nullFilterError(what, name, i)
			}
		}
	}
	return nil
}

// refuseNullFiltersYAML is the same refusal for the YAML path, which
// decodes the same two spellings into the same two wrong answers.
func refuseNullFiltersYAML(unmarshal func(any) error, what string, names ...string) error {
	var mapping map[string]any
	if err := unmarshal(&mapping); err != nil {
		return nil // not a mapping; the typed decode reports it
	}
	for _, name := range names {
		value, present := mapping[name]
		if !present {
			continue
		}
		if value == nil {
			return nullFilterError(what, name, -1)
		}
		items, ok := value.([]any)
		if !ok {
			continue
		}
		for i, item := range items {
			if item == nil {
				return nullFilterError(what, name, i)
			}
		}
	}
	return nil
}

// UnmarshalJSON collects unknown members into Extra.
func (c *ZkpReqFormat) UnmarshalJSON(data []byte) error {
	if err := refuseNullFiltersJSON(data, "zkp_req client metadata",
		"proof_system_values", "system_id_values"); err != nil {
		return err
	}
	knownObject, extra, err := splitMembers(data, "zkp_req client metadata", "proof_system_values", "system_id_values")
	if err != nil {
		return err
	}
	type plain ZkpReqFormat
	var known plain
	if err := decodeExact(knownObject, &known); err != nil {
		return err
	}
	*c = ZkpReqFormat(known)
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

// splitMembers separates data's top-level members into the ones named in
// known, re-encoded as an object for the struct decode, and every other
// member, which survives as an extension and is written back unchanged.
//
// Both halves have to agree on what a member NAME is, and they did not.
// encoding/json matches a struct field case-insensitively, so
// "CIRCUIT_ID_VALUES" bound to SystemIDValues; the extension half matched
// exactly, so the very same member was ALSO kept as unknown. Re-encoding
// then wrote both, and an extension nobody modelled silently rewrote a
// modelled member: {"system_id_values":[],"CIRCUIT_ID_VALUES":["urn:x"]}
// came back with BOTH arrays naming urn:x - a filter that matches nothing
// turned into one that permits that circuit.
//
// Selecting the known members by exact name BEFORE the decode settles it
// for every type that carries an extension bag: the struct only ever sees
// members spelled the way it declares them, and a differently cased name
// is an unknown member like any other. The members are carried across as
// raw bytes, so a number still reaches the struct exactly as written.
func splitMembers(data []byte, what string, known ...string) ([]byte, map[string]any, error) {
	// Before the map decode below, which keeps the LAST of a repeated
	// member and silently drops the rest - and the extension values are
	// decoded into any, so a duplicate nested inside one does not survive
	// either.
	//
	// Refused rather than quietly reduced, as the YAML side already does:
	// {"system_id_values":[],"system_id_values":["urn:x"]} re-encoded
	// as just ["urn:x"], turning a filter that matches NOTHING into one
	// that permits that circuit. The credential query was the only bag
	// that survived this, and only because its decode failure routes the
	// bytes to Raw, where they are kept verbatim.
	if hasDuplicateMembers(data) {
		return nil, nil, fmt.Errorf("%s: this names a member more than once, which cannot survive a decode", what)
	}

	var all map[string]json.RawMessage
	if err := decodeExact(data, &all); err != nil {
		return nil, nil, err
	}

	selected := make(map[string]json.RawMessage, len(known))
	for _, name := range known {
		if raw, ok := all[name]; ok {
			selected[name] = raw
			delete(all, name)
		}
	}
	knownObject, err := json.Marshal(selected)
	if err != nil {
		return nil, nil, err
	}
	if len(all) == 0 {
		return knownObject, nil, nil
	}

	extra := make(map[string]any, len(all))
	for name, raw := range all {
		var value any
		if err := decodeExact(raw, &value); err != nil {
			return nil, nil, err
		}
		extra[name] = value
	}
	return knownObject, extra, nil
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

// yamlValue decodes a YAML value while keeping each numeric scalar's
// ORIGINAL TEXT.
//
// yaml.v2 resolves a non-integer scalar to a float64 and discards the
// lexeme (vendor/gopkg.in/yaml.v2/resolve.go), so a configured
// 1.00000000000000001 is already 1 by the time any check here could look
// at it - and a check downstream then sees a value that is perfectly
// stable, because the damage is upstream of it. Integers survive yaml.v2
// intact; it is the decimals that do not.
//
// A req param is an input to a proof, so this is the one place in the
// configuration where that matters: the wallet hashes what it is given,
// and a parameter that quietly became a different number yields a
// different pseudonym.
//
// The lexeme is recoverable because yaml.v2 will decode any scalar into a
// string field. When it is also a valid JSON number it is carried as a
// json.Number, which encodes back out as exactly those digits. When it is
// not - YAML's 0x10, 1_000, .inf have no JSON spelling - the resolved
// value is kept, since inventing one would be worse than the rounding.
type yamlValue struct{ value any }

func (v *yamlValue) UnmarshalYAML(unmarshal func(any) error) error {
	var typed any
	if err := unmarshal(&typed); err != nil {
		return err
	}
	switch resolved := typed.(type) {
	case float64:
		// .inf and .nan are YAML numbers with no JSON spelling at all.
		// Left alone they reach json.Marshal, which refuses them - so the
		// whole request object becomes unencodable at SEND time, a long
		// way from the configuration that caused it.
		if math.IsInf(resolved, 0) || math.IsNaN(resolved) {
			return &unrepresentableScalarError{message: fmt.Sprintf(
				"%v %s: it has no JSON spelling at all, so it cannot be sent as a proof input", resolved, unrepresentableScalarMarker)}
		}
		var lexeme string
		if err := unmarshal(&lexeme); err == nil && isJSONNumber(lexeme) {
			v.value = json.Number(lexeme)
			return nil
		}
	case int, int64, uint64:
		var lexeme string
		if err := unmarshal(&lexeme); err == nil && isJSONNumber(lexeme) {
			v.value = json.Number(lexeme)
			return nil
		}
	case time.Time:
		// Does not happen on yaml.v2, which sets a timestamp-resolved
		// scalar as a string when the destination is an interface -
		// deliberately, for backward compatibility, and with a
		// "TODO(v3) Drop this" beside it (decode.go, the
		// yaml_TIMESTAMP_TAG branch). That TODO is the reason this case
		// exists.
		//
		// If it ever does happen, the damage is specific and severe: the
		// rulebook's age_check takes full-dates, so `ge: 2008-10-10`
		// would be emitted as "2008-10-10T00:00:00Z" - a value the
		// matcher rejects as not a full-date, from a template that reads
		// as perfectly correct. The lexeme is recoverable the same way a
		// number's is, so recovering it costs nothing and removes the
		// dependency on a compatibility hack someone else has already
		// scheduled for removal.
		var lexeme string
		if err := unmarshal(&lexeme); err == nil {
			v.value = lexeme
			return nil
		}
	case string:
		// yaml.v2 resolves a numeric literal it cannot hold - 1e400 -
		// into a STRING, and nothing in the value it hands back says
		// whether the operator wrote 1e400 or "1e400". So a number
		// quietly becomes a string, which for a proof input is a changed
		// request that no check downstream can see: a string always looks
		// perfectly stable.
		//
		// Refused rather than guessed. A value at this magnitude is not
		// usable as a proof input whichever of the two was meant, so a
		// refusal costs nothing real, and a silent type change costs a
		// pseudonym that does not match.
		if outOfRangeNumericSpelling(resolved) {
			return &unrepresentableScalarError{message: fmt.Sprintf(
				"%q %s: yaml.v2 resolves a literal outside its range to a string, so it cannot tell %s from %q and neither can this",
				resolved, unrepresentableScalarMarker, resolved, resolved)}
		}
	// Errors from the nested decodes are RETURNED, not swallowed. They
	// are this type's own refusals - a scalar with no JSON number to
	// become - and a fallback here would discard the refusal and keep
	// exactly the value it exists to reject. (A shape yaml.v2 can put in
	// a map[any]any it can also put in a map[any]yamlValue, since
	// yamlValue accepts anything, so there is no structural error to fall
	// back from either.)
	case map[any]any:
		var mapping map[any]yamlValue
		if err := unmarshal(&mapping); err != nil {
			return err
		}
		out := make(map[any]any, len(mapping))
		for key, item := range mapping {
			out[key] = item.value
		}
		v.value = out
		return nil
	case []any:
		var sequence []yamlValue
		if err := unmarshal(&sequence); err != nil {
			return err
		}
		out := make([]any, len(sequence))
		for i, item := range sequence {
			out[i] = item.value
		}
		v.value = out
		return nil
	}
	v.value = typed
	return nil
}

// outOfRangeNumericSpelling reports whether a value yaml.v2 handed back
// as a string is in fact a JSON number spelling that overflows a float64 -
// which is how yaml.v2 reports one it cannot resolve.
func outOfRangeNumericSpelling(value string) bool {
	if !json.Valid([]byte(value)) {
		return false // not a number spelling at all
	}
	var numeric *strconv.NumError
	_, err := strconv.ParseFloat(value, 64)
	return errors.As(err, &numeric) && errors.Is(numeric.Err, strconv.ErrRange)
}

// isJSONNumber reports whether literal is spelled the way JSON spells a
// number. YAML admits several that JSON does not.
func isJSONNumber(literal string) bool {
	if _, err := strconv.ParseFloat(literal, 64); err != nil {
		return false
	}
	return json.Valid([]byte(literal))
}

// MarshalYAML flattens Extra alongside the known members.
func (r ReqItem) MarshalYAML() (any, error) {
	m := map[string]any{"id": r.FnID, "return": r.Return}
	if r.Params != nil {
		m["params"] = r.Params
	}
	return mergeExtraYAML(m, r.Extra, declaredJSONKeys(reflect.TypeOf(ReqItem{})), "_req item")
}

// UnmarshalYAML captures every member other than the modelled ones.
func (r *ReqItem) UnmarshalYAML(unmarshal func(any) error) error {
	if err := refuseDuplicateYAMLKeys(unmarshal, "_req item"); err != nil {
		return err
	}
	type plain ReqItem // no methods, so yaml.v2 uses the struct tags
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("req item: %w", err)
	}
	*r = ReqItem(known)

	// Params is decoded a second time, keeping each numeric scalar's
	// original text. See yamlValue: yaml.v2 resolves a non-integer scalar
	// to a float64 before anything here runs, so the lexeme is the only
	// place the configured precision still exists.
	var lexemes struct {
		Params yamlValue `yaml:"params"`
	}
	if err := unmarshal(&lexemes); err != nil {
		return err
	}
	if lexemes.Params.value != nil {
		if params, ok := lexemes.Params.value.(map[any]any); ok {
			r.Params = nil
			for key, item := range params {
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("req item params: %v is not a string key, and has no JSON spelling", key)
				}
				if r.Params == nil {
					r.Params = make(map[string]any, len(params))
				}
				r.Params[name] = item
			}
		}
	}

	// Params is an open tree, so it needs the same walk Extra gets. The
	// struct tag puts it in a map[string]any, but yaml.v2 leaves every
	// NESTED mapping inside it as map[any]any - and this item is emitted
	// as JSON, where a key with no JSON spelling is coerced to its
	// rendering or, for a sequence key, dropped without a word. A function
	// parameter is the one place a configuration must survive unchanged:
	// it is an input to a proof, so a changed one yields a different
	// pseudonym and the failure appears nowhere near here.
	//
	// (A nested tree whose keys are all strings encodes correctly through
	// encoding/json on this toolchain either way. The walk is here so that
	// staying correct is this code's decision rather than that package's.)
	params, err := normaliseYAML(r.Params, "req item params")
	if err != nil {
		return err
	}
	if params != nil {
		normalised, ok := params.(map[string]any)
		if !ok {
			return fmt.Errorf("req item params: expected a mapping, got %T", params)
		}
		r.Params = normalised
	}

	extra, err := yamlExtra(unmarshal, "_req item", "fn_id", "return", "params")
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

// MarshalYAML flattens Extra alongside the known members.
func (c ZkpReqFormat) MarshalYAML() (any, error) {
	m := map[string]any{}
	if c.ProofSystemValues != nil {
		m["proof_system_values"] = c.ProofSystemValues
	}
	if c.SystemIDValues != nil {
		m["system_id_values"] = c.SystemIDValues
	}
	return mergeExtraYAML(m, c.Extra, declaredJSONKeys(reflect.TypeOf(ZkpReqFormat{})), "zkp_req client metadata")
}

// UnmarshalYAML captures every member other than the modelled ones -
// including the rulebook example's fn_id and input, which is the shape an
// operator is most likely to need and the one this could not express.
func (c *ZkpReqFormat) UnmarshalYAML(unmarshal func(any) error) error {
	if err := refuseDuplicateYAMLKeys(unmarshal, "zkp_req client metadata"); err != nil {
		return err
	}
	if err := refuseNullFiltersYAML(unmarshal, "zkp_req client metadata",
		"proof_system_values", "system_id_values"); err != nil {
		return err
	}
	type plain ZkpReqFormat
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("zkp_req client metadata: %w", err)
	}
	*c = ZkpReqFormat(known)

	extra, err := yamlExtra(unmarshal, "zkp_req client metadata",
		"proof_system_values", "system_id_values")
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

// refuseDuplicateYAMLKeys reports a mapping key repeated at any depth.
//
// yaml.v2's non-strict Unmarshal keeps the LAST of a repeated key, and
// the configuration loaders use it, so
//
//	circuit_id_values: []
//	circuit_id_values: [urn:unexpected]
//
// loaded cleanly and emitted only the second - a filter matching NOTHING
// replaced by one that permits that circuit, with nothing malformed to
// point at. A repeated nested parameter went the same way, and a proof
// input quietly taking its last spelling is the same defect one level
// down.
//
// MapSlice is the one decode target that keeps repeats, and yaml.v2 uses
// it for nested mappings too once the top level asks for it, so a single
// decode and one walk cover every depth. The JSON side refuses the same
// shape in splitMembers; this is that guard for the other format.
func refuseDuplicateYAMLKeys(unmarshal func(any) error, what string) error {
	var document yamlv2.MapSlice
	if err := unmarshal(&document); err != nil {
		return nil // not a mapping; the typed decode reports it
	}
	return walkYAMLDuplicates(document, what, nil)
}

func walkYAMLDuplicates(value any, what string, path []string) error {
	switch typed := value.(type) {
	case yamlv2.MapSlice:
		seen := make(map[string]bool, len(typed))
		for _, item := range typed {
			key := fmt.Sprint(item.Key)
			if seen[key] {
				where := key
				if len(path) > 0 {
					where = strings.Join(append(path, key), ".")
				}
				return fmt.Errorf("%s: %s is named more than once, and YAML keeps only the last", what, where)
			}
			seen[key] = true
			if err := walkYAMLDuplicates(item.Value, what, append(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range typed {
			if err := walkYAMLDuplicates(item, what, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	return nil
}

// yamlExtra decodes the same node a second time as a mapping and returns
// every member not named in known, normalised.
func yamlExtra(unmarshal func(any) error, what string, known ...string) (map[string]any, error) {
	// Through yamlValue, not a plain map[string]any: yaml.v2 resolves a
	// decimal scalar to a float64 and discards the lexeme, so an unknown
	// member carrying 1.00000000000000001 would arrive here as 1 and
	// every check downstream would see a value that is perfectly stable.
	//
	// An extension member is as much a proof input as a modelled one -
	// more so, since the shapes this bag exists for are the ones a newer
	// rulebook defines and this build does not understand. Preserving
	// params and rounding these would be a distinction with no basis.
	var tree yamlValue
	if err := unmarshal(&tree); err != nil {
		// EVERY error, not just yamlValue's own refusals.
		//
		// This used to swallow anything else on the reasoning that the
		// typed decode above had already reported it. That is true of a
		// node which is not a mapping - and nothing else. A structural
		// fault the typed decode simply IGNORES, such as a sequence used
		// as a map key under an unknown member, reaches here as a real
		// error, and discarding it discarded the whole extension bag
		// with it: a metadata block carrying fn_id, input and one
		// malformed sibling loaded with NO extensions at all, silently,
		// and the verifier sent different metadata than was configured.
		//
		// The not-a-mapping case needs no special handling here: it is
		// refused by the typed decode before this function is called,
		// and if it ever did arrive the type assertion below returns it
		// as "no extensions" without an error.
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	all, ok := tree.value.(map[any]any)
	if !ok {
		return nil, nil // not a mapping; as above
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

// unrepresentableScalarError is yamlValue's own refusal: a scalar that
// cannot be carried as the number it was written as.
//
// A distinct type rather than a message to match on, because the caller
// has to tell this apart from a structural mismatch - which is not its to
// report, the typed decode having already said what is wrong with the
// shape - and matching on wording would break the first time the wording
// improved.
type unrepresentableScalarError struct{ message string }

func (e *unrepresentableScalarError) Error() string { return e.message }

// isUnrepresentableScalar reports whether err is such a refusal,
// including through whatever yaml.v2 wraps it in.
func isUnrepresentableScalar(err error) bool {
	var refusal *unrepresentableScalarError
	if errors.As(err, &refusal) {
		return true
	}
	// yaml.v2 collects errors from nested UnmarshalYAML calls into a
	// TypeError that keeps only their messages, so the chain does not
	// always survive. The marker is this package's own wording, emitted
	// nowhere else.
	return strings.Contains(err.Error(), unrepresentableScalarMarker)
}

const unrepresentableScalarMarker = "cannot be carried as a number"

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
	normalised, err := checkYAMLRendersNumbersExactly(m, what, nil)
	if err != nil {
		return nil, err
	}
	return normalised, nil
}

// checkYAMLRendersNumbersExactly refuses to emit a number yaml.v2 would
// round on its way out.
//
// The YAML marshal path bridges through JSON, so an exactly-preserved
// param arrives here as a json.Number - and yaml.v2 encodes one by trying
// Int64 and falling back to Float64 (vendor/gopkg.in/yaml.v2/encode.go).
// An integer beyond int64, or a decimal with more digits than a float64
// holds, is therefore RENDERED DIFFERENTLY than it was configured.
//
// An error rather than a silent rounding, and rather than a repair.
// These numbers are inputs to a proof: a changed one yields a different
// pseudonym, and the symptom is two systems disagreeing about who someone
// is with nothing malformed to point at. Every other path keeps them
// exact - the YAML decode keeps the lexeme, JSON keeps the literal - so
// this is the one place where the honest answer is to stop.
func checkYAMLRendersNumbersExactly(value any, what string, path []string) (any, error) {
	// Normalised first, so the walk below sees one shape of container
	// whatever the caller assembled. Without this it descended only
	// map[string]any and []any, and a TYPED container - a
	// map[string]json.Number, a []json.Number - was skipped: yaml.v2 then
	// rounded what was inside it with nothing said.
	//
	// CredentialQuery.MarshalYAML happened to be safe, because it bridges
	// through JSON before calling this. ReqItem.MarshalYAML builds its
	// map directly and was not. Relying on which caller normalises is the
	// kind of correctness that holds until someone adds a third caller.
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	// Before the normalisation below, which would drop one silently. A
	// raw leaf is embedded verbatim by Marshal, so a duplicate inside one
	// surfaces here whatever container it sat in and however deep.
	if hasDuplicateMembers(encoded) {
		return nil, fmt.Errorf("%s: this names a member more than once, which YAML cannot write without dropping one", what)
	}
	var normalised any
	if err := decodeExact(encoded, &normalised); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := walkYAMLNumbers(normalised, what, path); err != nil {
		return nil, err
	}
	// The NORMALISED tree, not the caller's. The check above ran on this
	// shape while the caller went on to hand yaml.v2 its own containers,
	// where a json.RawMessage is a []byte - written out as a sequence of
	// byte integers rather than the object it encodes.
	return normalised, nil
}

func walkYAMLNumbers(value any, what string, path []string) error {
	switch typed := value.(type) {
	case json.Number:
		if yamlRendersNumberExactly(typed.String()) {
			return nil
		}
		where := "a number"
		if len(path) > 0 {
			where = strings.Join(path, ".")
		}
		return fmt.Errorf("%s: %s is %s, which YAML cannot write without changing it; "+
			"a proof input has to survive the round trip, so quote it as a string if the exact digits are what you mean",
			what, where, typed.String())
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(typed)) {
			if err := walkYAMLNumbers(typed[key], what, append(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range typed {
			if err := walkYAMLNumbers(item, what, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	return nil
}

// yamlRendersNumberExactly reports whether yaml.v2 writes literal back as
// the same number: exactly for an integer it can hold in an int64, and
// otherwise via a float64, whose shortest rendering has to denote the
// same value.
func yamlRendersNumberExactly(literal string) bool {
	if _, err := strconv.ParseInt(literal, 10, 64); err == nil {
		return true
	}
	exact, ok := new(big.Rat).SetString(literal)
	if !ok {
		return false
	}
	asFloat, err := strconv.ParseFloat(literal, 64)
	if err != nil || math.IsInf(asFloat, 0) || math.IsNaN(asFloat) {
		return false
	}
	rendered, ok := new(big.Rat).SetString(strconv.FormatFloat(asFloat, 'g', -1, 64))
	return ok && rendered.Cmp(exact) == 0
}
