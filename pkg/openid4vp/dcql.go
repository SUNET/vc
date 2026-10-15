package openid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/vc20/credential"
)

type DCQL struct {
	// Credentials REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that specify the requested Credentials.
	Credentials []CredentialQuery `json:"credentials" yaml:"credentials" validate:"required,min=1,dive,required"`

	// CredentialSets OPTIONAL. A non-empty array of Credential Set Queries as defined in Section 6.2 that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty" yaml:"credential_sets,omitempty" validate:"omitnil,min=1,dive,required"`
}

// CredentialQuery is an object representing a request for a presentation of one or more matching Credentials.
type CredentialQuery struct {
	// ID REQUIRED. A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	ID string `json:"id" yaml:"id" validate:"required"`

	// Format REQUIRED. A string that specifies the format of the requested Credential. Valid Credential Format Identifier values are defined in Appendix B.
	Format string `json:"format" yaml:"format" validate:"required"`

	// Multiple OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	//
	// A POINTER, for the same reason RequireCryptographicHolderBinding
	// below is one: with a plain bool, omitempty cannot tell an absent
	// member from an explicit false, so `"multiple": false` - an
	// ordinary, valid query - did not encode back to what arrived and
	// was kept as Raw. That is not a harmless detour: a raw query is
	// emitted from its original bytes, so augmentDCQLFromVCTM's rewrite
	// of the shadow Claims was silently discarded and the request went
	// out with the un-augmented paths.
	Multiple *bool `json:"multiple,omitempty" yaml:"multiple,omitempty"`

	// Meta REQUIRED. An object defining additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. Examples of those are in Appendix B.3.5 and Appendix B.2.3. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta MetaQuery `json:"meta" yaml:"meta" validate:"required"`

	// TrustedAuthorities OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty" yaml:"trusted_authorities,omitempty"`

	// RequireCryptographicHolderBinding OPTIONAL. Spec default is true when omitted; nil pointer preserves that distinction from an explicit false.
	RequireCryptographicHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty" yaml:"require_cryptographic_holder_binding,omitempty"`

	// Claims OPTIONAL. A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimQuery `json:"claims,omitempty" yaml:"claims,omitempty"`

	// ClaimSet OPTIONAL. A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested. The rules for selecting claims to send are defined in Section 6.4.1.
	ClaimSet [][]string `json:"claim_sets,omitempty" yaml:"claim_sets,omitempty" validate:"omitnil,min=1,dive,required,min=1,dive,required"`

	// Req is the circuit_zk format's list of requested calculations.
	//
	// It replaces Claims rather than accompanying it: a circuit_zk
	// presentation discloses no issuer-signed attribute at all, so every
	// value a Verifier wants is the output of a function named here. A
	// query carrying both is one the planner rejects - which this does
	// not prevent, because sending it is how a wallet gets tested.
	Req []ReqItem `json:"req,omitempty" yaml:"req,omitempty"`

	// Extra carries members this build does not know about, flattened
	// alongside the known ones.
	//
	// The request shape is moving - the nym_auth rulebook, OpenID4VP and
	// the DC API all - and wallets of several generations will be in the
	// field at once. Without somewhere to put a member this code has never
	// heard of, talking to any of them means waiting for a release here.
	Extra map[string]any `json:"-" yaml:"-"`

	// Raw replaces this query entirely: when set, it is emitted as this
	// JSON VALUE and every other modelled member is ignored on the wire.
	//
	// The value, not the bytes. encoding/json compacts and HTML-escapes
	// whatever a MarshalJSON returns, so an operator's whitespace is
	// dropped and a & inside a string is written \u0026 - which no
	// conformant wallet can tell apart from what was configured, and
	// which nothing here can prevent short of re-implementing the
	// request-object encoder. What IS guaranteed is that every member,
	// its nesting, and every value survives unchanged, including members
	// this build has never heard of and numeric literals it would
	// otherwise reformat.
	//
	// Extra covers a shape that ADDS members. This covers one that changes
	// the type of a member already modelled - the rulebook's WIP example
	// makes "claims" an object where DCQL has an array, and a future
	// generation could do the same to "req" or "meta". A per-member
	// override for each of those is a field this struct grows every time a
	// specification moves; one raw escape hatch covers all of them and
	// needs no release here.
	//
	// It is deliberately all-or-nothing. A half-raw query would leave an
	// operator guessing which of the two sources a given member came from.
	Raw json.RawMessage `json:"-" yaml:"-"`
}

// MarshalYAML flattens Extra alongside the known members, so a query read
// from configuration can be written back out whole.
func (q CredentialQuery) MarshalYAML() (any, error) {
	// Raw is tagged yaml:"-", so the bridge below would emit only the
	// modelled shadow - a DIFFERENT query, missing whatever made these
	// bytes raw in the first place, and missing it silently.
	if q.Raw != nil {
		if q.Extra != nil {
			return nil, fmt.Errorf("credential query: raw and extra are both set, and raw would discard extra")
		}
		if !json.Valid(q.Raw) {
			return nil, fmt.Errorf("credential query: raw is not valid JSON")
		}
		// A duplicate member has no YAML representation that keeps both.
		// This path decodes the bytes to a tree, which collapses them to
		// the last value - so writing the configuration back out would
		// emit a DIFFERENT request, and the whole reason such a query is
		// carried raw is that it must not change. Refused rather than
		// quietly reduced; the JSON path still carries it.
		if hasDuplicateMembers(q.Raw) {
			return nil, fmt.Errorf("credential query: this query names a member more than once, which YAML cannot write without dropping one")
		}
		var tree any
		if err := decodeExact(q.Raw, &tree); err != nil {
			return nil, fmt.Errorf("credential query: %w", err)
		}
		// decodeExact keeps numbers as their literals; this refuses the
		// ones yaml.v2 would round on the way out, rather than writing a
		// different number than the one configured.
		if err := checkYAMLRendersNumbersExactly(tree, "credential query", nil); err != nil {
			return nil, err
		}
		return tree, nil
	}
	type plain CredentialQuery
	encoded, err := json.Marshal(plain(q))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := decodeExact(encoded, &m); err != nil {
		return nil, err
	}
	return mergeExtraYAML(m, q.Extra, declaredJSONKeys(reflect.TypeOf(CredentialQuery{})), "credential query")
}

// UnmarshalYAML captures every member other than the modelled ones.
//
// Without it a presentation request template - which pkg/configuration
// loads from YAML into an openid4vp.DCQL - could not carry a member this
// build does not model, which is the whole purpose of Extra.
//
// The known members go through a methodless alias so yaml.v2 applies the
// struct tags and reports a wrong type itself, rather than this coercing
// one. See the note above ReqItem.UnmarshalYAML for why nothing here
// passes through JSON on the way.
func (q *CredentialQuery) UnmarshalYAML(unmarshal func(any) error) error {
	type plain CredentialQuery
	var known plain
	if err := unmarshal(&known); err != nil {
		// Same fallback as the JSON decode, for the same reason: a shape
		// the typed model cannot hold - claims as a mapping, say - is
		// kept rather than refused. Without it this type would refuse to
		// read back a query it had just written, since MarshalYAML above
		// emits exactly such a shape.
		raw, rawErr := rawFromYAML(unmarshal)
		if rawErr != nil {
			return fmt.Errorf("credential query: %w", err)
		}
		// On the NORMALISED bytes, which is what will be emitted and
		// what a wallet will read. A template is as capable of naming a
		// constraint twice, or in the wrong case, as a JSON request is.
		if checkErr := checkRawConstraints(raw); checkErr != nil {
			return checkErr
		}
		fallback := CredentialQuery{Raw: raw}
		if _, invalid := fallback.adoptRawShadowReporting(); len(invalid) > 0 {
			// A member of the right JSON kind that the model still
			// rejects is an invalid query, not an unmodelled one. See the
			// JSON decode.
			return fmt.Errorf("credential query: %w", err)
		}
		*q = fallback
		return nil
	}
	*q = CredentialQuery(known)

	extra, err := yamlExtra(unmarshal, "credential query",
		"id", "format", "multiple", "meta", "trusted_authorities",
		"require_cryptographic_holder_binding", "claims", "claim_sets", "req")
	if err != nil {
		return err
	}
	q.Extra = extra

	// The same question the JSON decode asks, and for the same reason:
	// did it decode, or did it keep everything? A template carrying
	// `req: []`, an item with no `id`, or `params: null` decodes into zero
	// values that are then re-emitted with members added or removed - and
	// those are exactly the negative requests an operator configures this
	// verifier to send.
	//
	// Compared on SHAPE rather than value, which is the one difference
	// from the JSON path. yaml.v2 coerces a scalar to the field's type -
	// `id: 7` becomes "7" - for every configuration struct in this
	// repository, and that policy is deliberate; treating it as loss here
	// would send every template with a numeric-looking scalar down the raw
	// path and quietly reverse it. Presence, absence and nesting are what
	// the typed model changes, and what this catches.
	original, rawErr := rawFromYAML(unmarshal)
	if rawErr != nil {
		return rawErr
	}
	reencoded, encErr := json.Marshal(*q)
	if encErr != nil {
		return encErr
	}
	if !jsonShapeEquivalent(original, reencoded) {
		// The second YAML route to Raw, and the same guard. Missing it
		// here was the whole of the first fix's incompleteness: a
		// template with a case-aliased constraint takes THIS path, not
		// the decode-failure one above.
		if err := checkRawConstraints(original); err != nil {
			return err
		}
		fallback := CredentialQuery{Raw: original}
		fallback.adoptRawShadow()
		*q = fallback
	}
	return nil
}

// jsonShapeEquivalent reports whether two JSON documents have the same
// members, nesting and array lengths - ignoring scalar types.
//
// Scalars are not compared because yaml.v2's coercion is this
// repository's settled policy, not a loss: `id: 7` arriving as "7" is how
// every other configuration struct here behaves, and diverging for this
// one type would be worse than the coercion. What a typed decode DOES
// lose is structural - an empty array dropped by omitempty, an absent
// member becoming an empty string, a null becoming nothing at all - and
// that is what this sees.
func jsonShapeEquivalent(a, b json.RawMessage) bool {
	decode := func(data []byte) (any, bool) {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		return value, true
	}
	left, ok := decode(a)
	if !ok {
		return false
	}
	right, ok := decode(b)
	if !ok {
		return false
	}
	return sameJSONShape(left, right)
}

func sameJSONShape(a, b any) bool {
	switch left := a.(type) {
	case map[string]any:
		right, ok := b.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for name, value := range left {
			other, present := right[name]
			if !present || !sameJSONShape(value, other) {
				return false
			}
		}
		return true
	case []any:
		right, ok := b.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !sameJSONShape(left[i], right[i]) {
				return false
			}
		}
		return true
	case nil:
		// null is a value an operator wrote, not an absence. Dropping it
		// is the loss this exists to catch, so it only matches null.
		return b == nil
	default:
		// A scalar matches any other scalar: see the doc comment.
		switch b.(type) {
		case map[string]any, []any, nil:
			return false
		}
		return true
	}
}

// rawFromYAML reads a whole YAML value and returns it as JSON, keeping
// each numeric scalar's original text.
//
// Through yamlValue rather than a plain any, so a decimal does not lose
// its digits on the way in - see that type. Non-string keys are refused
// by normaliseYAML rather than coerced, since JSON has no spelling for
// them.
func rawFromYAML(unmarshal func(any) error) (json.RawMessage, error) {
	var tree yamlValue
	if err := unmarshal(&tree); err != nil {
		return nil, err
	}
	normalised, err := normaliseYAML(tree.value, "credential query")
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalised)
}

// MarshalJSON flattens Extra alongside the known members.
//
// With Extra empty this is byte-identical to the struct encoding it
// replaces, which TestCredentialQueryEncodingUnchanged pins: every format
// other than circuit_zk goes through here too, and none of them should be
// able to tell this method exists.
func (q CredentialQuery) MarshalJSON() ([]byte, error) {
	// Returned as-is, which encoding/json then compacts and HTML-escapes
	// on its way into the enclosing document. See Raw's own comment for
	// why the guarantee is on the JSON value rather than the bytes.
	if q.Raw != nil {
		if q.Extra != nil {
			return nil, fmt.Errorf("credential query: raw and extra are both set, and raw would discard extra")
		}
		if !json.Valid(q.Raw) {
			return nil, fmt.Errorf("credential query: raw is not valid JSON")
		}
		return q.Raw, nil
	}
	type plain CredentialQuery // no methods, so no recursion
	return marshalWithExtra(plain(q), q.Extra, "credential query")
}

// UnmarshalJSON collects unknown members into Extra.
func (q *CredentialQuery) UnmarshalJSON(data []byte) error {
	type plain CredentialQuery
	var known plain
	if err := decodeExact(data, &known); err != nil {
		// A shape the model cannot hold is kept as it stands rather than
		// refused. Decoding has to be TOTAL for the escape hatch to be
		// worth anything: a request object is JSON-encoded into the HA
		// cache and read back by another node, so a raw query with - say -
		// an object at "claims" would be written out fine and then fail to
		// load anywhere but the node that built it.
		//
		// It also keeps the verifier's own promise. This serialiser does
		// not repair a request, and refusing to read back something it
		// just wrote would be a repair by other means.
		if !json.Valid(data) {
			return err
		}
		// Before anything is kept raw. A typed decode failing is exactly
		// how a duplicate or case-aliased constraint used to get past
		// these checks: the shadow still reported the constraint, so
		// validation passed, while the emitted bytes said something else.
		if checkErr := checkRawConstraints(data); checkErr != nil {
			return checkErr
		}
		fallback := CredentialQuery{Raw: append(json.RawMessage(nil), data...)}
		if _, invalid := fallback.adoptRawShadowReporting(); len(invalid) > 0 {
			// A member of the right JSON kind that the model still
			// rejects is an ordinary query that is simply invalid, not a
			// shape this build has never seen. Sending it to Raw would
			// launder a decode error into a query that validates - the
			// SD-JWT and mdoc rules read the shadow, and an unreadable
			// member leaves nothing there to judge.
			return err
		}
		*q = fallback
		return nil
	}
	*q = CredentialQuery(known)
	extra, err := unknownMembers(data,
		"id", "format", "multiple", "meta", "trusted_authorities",
		"require_cryptographic_holder_binding", "claims", "claim_sets", "req")
	if err != nil {
		return err
	}
	q.Extra = extra

	// A decode that SUCCEEDED is not necessarily one that kept
	// everything. `"req": []` decodes to an empty slice and is then
	// dropped by omitempty; an item missing "id" decodes to "" and comes
	// back as a member that was not there. Those shapes are exactly the
	// ones a Verifier sends on purpose to see what a wallet does with
	// them, and the HA cache round trip would quietly repair them.
	//
	// So the test is not "did it decode" but "does it encode back to what
	// arrived". Anything that does not is kept as it stands.
	if ambiguous := ambiguousConstraintMembers(data); len(ambiguous) > 0 {
		return &DCQLValidationError{
			Field: strings.Join(ambiguous, ", "),
			Message: "named more than once, and JSON decoders disagree about which value wins; " +
				"a request whose constraint depends on the reader is one this verifier will not sign",
		}
	}
	if hasDuplicateMembers(data) || !q.encodesBackTo(data) {
		// The same guard on the way in here. A case-aliased member is one
		// of the things that makes a query fail to encode back, so this
		// is the path it takes.
		if err := checkRawConstraints(data); err != nil {
			return err
		}
		*q = CredentialQuery{Raw: append(json.RawMessage(nil), data...)}
		q.adoptRawShadow()
	}
	return nil
}

// ambiguousConstraintMembers names the members that decide what a request
// is LIMITED TO and appear more than once.
//
// A duplicate is a parser differential: encoding/json keeps the last
// value, other decoders keep the first, and the two disagree about what
// the document says. For most members that is a curiosity this verifier
// passes through, because sending a malformed request is how a wallet
// gets tested. For the members validation reads it is not.
//
// {"format":"dc+sd-jwt","meta":{},"meta":{"vct_values":["urn:x"]}} is the
// shape: Go validates against the LAST meta, finds a constraint, signs
// and sends - while a first-wins wallet reads an unconstrained SD-JWT
// request and may return anything it holds. The query arrives at the
// ingress from a browser, so that is attacker-reachable over-disclosure,
// reached through the very escape hatch added to preserve malformed
// requests.
//
// So these are refused rather than carried, wherever they come from. A
// request whose constraint depends on who is reading it is not one to
// sign on anybody's behalf - and the negative-test cases that matter
// (the rulebook's own uniqueness rules on req ids and handles) are deeper
// in the document and still pass through untouched.
func ambiguousConstraintMembers(data []byte) []string {
	members, ok := topLevelMemberNames(data)
	if !ok {
		return nil
	}

	var ambiguous []string
	for _, name := range []string{"format", "meta"} {
		if members[name] > 1 {
			ambiguous = append(ambiguous, name)
		}
	}

	// And inside meta, where the constraint itself lives. Only the last
	// one can be read back, which is the same reading validation uses, so
	// checking it is enough to catch a constraint that differs between
	// decoders.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err == nil {
		if nested, present := envelope["meta"]; present {
			if inner, ok := topLevelMemberNames(nested); ok {
				for _, name := range slices.Sorted(maps.Keys(inner)) {
					if inner[name] > 1 {
						ambiguous = append(ambiguous, "meta."+name)
					}
				}
			}
		}
	}
	slices.Sort(ambiguous)
	return slices.Compact(ambiguous)
}

// aliasedConstraintMembers names the constraint members written in a case
// that is not the one the wire uses.
//
// Go's encoding/json matches field names case-insensitively, so
// {"meta":{"VCT_VALUES":["urn:x"]}} decodes into MetaQuery.VCTValues and
// the shadow reports a constraint - while the bytes this verifier signs
// carry VCT_VALUES, which no conformant wallet reads as vct_values. The
// request goes out unconstrained and validation believed otherwise.
//
// The same reasoning as the duplicate check beside it: a request whose
// constraint depends on who is reading it is one this verifier will not
// sign. Refused rather than quietly un-shadowed, because an alias is
// almost certainly a typo in a configuration, and a request that silently
// stops constraining anything is the worst way to discover that.
//
// Only the members validation reads. Everything else keeps passing
// through, because sending a shape this build has never seen is the whole
// point of the raw path.
func aliasedConstraintMembers(data []byte) []string {
	var aliased []string

	check := func(prefix string, document []byte, modelled ...string) {
		names, ok := topLevelMemberNames(document)
		if !ok {
			return
		}
		for name := range names {
			for _, want := range modelled {
				if name != want && strings.EqualFold(name, want) {
					aliased = append(aliased, prefix+name)
				}
			}
		}
	}

	check("", data, "format", "meta", "claims")

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err == nil {
		if nested, present := envelope["meta"]; present {
			check("meta.", nested, "vct_values", "doctype_value", "type_values")
		}
	}

	slices.Sort(aliased)
	return slices.Compact(aliased)
}

// topLevelMemberNames counts how often each member name appears in a JSON
// object, without descending into it.
func topLevelMemberNames(data []byte) (map[string]int, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, false
	}

	counts := map[string]int{}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		text, ok := name.(string)
		if !ok {
			return nil, false
		}
		counts[text]++
		if _, err := scanForDuplicateMembers(decoder); err != nil {
			return nil, false
		}
	}
	return counts, true
}

// hasDuplicateMembers reports whether any object in data names the same
// member twice, at any depth.
//
// encoding/json keeps the last one, and so does every other decoder in
// this repository, which makes a duplicate INVISIBLE to the
// encode-back-to comparison: {"id":"first","id":"last"} re-encodes as
// just "last" and compares equal to itself. The query is then sent with
// the duplicate silently removed.
//
// Two reasons that is not acceptable here. It is a changed request, and
// this serialiser does not change requests - a duplicate member is
// exactly the kind of malformed input a Verifier sends on purpose to see
// what a wallet does with it. And it is a parser differential: JSON
// decoders disagree about which value wins, so a request where that
// matters has to reach the wallet as written rather than as this build
// happens to read it.
//
// Detected rather than refused, because refusing would make the malformed
// request unsendable, which is the same loss by another route. A query
// carrying one simply goes down the raw path, where the bytes stand.
func hasDuplicateMembers(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	duplicate, err := scanForDuplicateMembers(decoder)
	if err != nil {
		// Malformed, which is not this function's business to report -
		// the caller has already established the bytes are valid JSON, or
		// is about to refuse them for being invalid.
		return false
	}
	return duplicate
}

// scanForDuplicateMembers consumes exactly one JSON value from decoder
// and reports whether it, or anything inside it, names a member twice.
//
// Written as a descent rather than a flat token loop because
// Decoder.Token reports member names and string values identically; only
// the structure says which is which.
func scanForDuplicateMembers(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil // a scalar, now consumed
	}

	duplicate := false
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return false, err
			}
			text, ok := name.(string)
			if !ok {
				return false, fmt.Errorf("object member name is not a string")
			}
			if seen[text] {
				duplicate = true
			}
			seen[text] = true

			inner, err := scanForDuplicateMembers(decoder)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || inner
		}
	case '[':
		for decoder.More() {
			inner, err := scanForDuplicateMembers(decoder)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || inner
		}
	default:
		return false, fmt.Errorf("unexpected delimiter %q", delim)
	}

	if _, err := decoder.Token(); err != nil { // the closing delimiter
		return false, err
	}
	return duplicate, nil
}

// encodesBackTo reports whether re-encoding q reproduces data, compared
// as JSON values rather than as bytes - member order and whitespace are
// not something this type promises to preserve, and treating them as loss
// would send every ordinary query down the raw path.
func (q CredentialQuery) encodesBackTo(data []byte) bool {
	reencoded, err := json.Marshal(q)
	if err != nil {
		return false
	}
	return jsonEquivalent(data, reencoded)
}

// jsonEquivalent compares two JSON documents by value.
//
// Numbers are compared as their literals (UseNumber), so a value that
// re-encoded with different precision counts as changed - which for a
// req param, an input to a proof, is exactly what it is.
func jsonEquivalent(a, b []byte) bool {
	decode := func(data []byte) (any, bool) {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		return value, true
	}
	left, ok := decode(a)
	if !ok {
		return false
	}
	right, ok := decode(b)
	if !ok {
		return false
	}
	return reflect.DeepEqual(left, right)
}

// NewRawCredentialQuery builds a query that is sent as exactly these
// bytes, with every modelled member it can read filled in alongside.
//
// This is the supported way to use the escape hatch. Writing
// CredentialQuery{Raw: ...} by hand compiles and is wrong: Raw is
// authoritative for the WIRE, and the rest of the stack reads the struct -
// UIInteraction records ID in the authorization context's scopes and the
// response path matches a presentation back to it, matching reads
// Meta.TypeValues, Multiple and RequireCryptographicHolderBinding decide
// what a response may contain. A hand-built query is therefore sent
// correctly and then tracked under defaults nobody chose, which fails as
// a result that cannot be matched rather than as an error.
//
// TestRawIsOnlyConstructedThroughTheConstructor keeps that from being
// advice: production code may not write the literal.
// checkRawConstraints refuses a raw query whose constraint members this
// verifier and a wallet would read differently.
//
// Shared by the constructor and by both decode fallbacks. The decode
// paths used to skip it, and that was the hole: an unmodelled member -
// `"req": {}` - made the typed decode fail, the query went raw, and the
// duplicate-meta check never ran. The shadow still reported the last
// meta's constraint, so validation passed while the request was emitted
// with BOTH, which a first-wins wallet reads as unconstrained. One
// function, three callers, no path that reaches Raw without passing here.
func checkRawConstraints(raw json.RawMessage) error {
	if ambiguous := ambiguousConstraintMembers(raw); len(ambiguous) > 0 {
		return fmt.Errorf(
			"credential query: %s named more than once, and JSON decoders disagree about which value wins",
			strings.Join(ambiguous, ", "))
	}
	if aliased := aliasedConstraintMembers(raw); len(aliased) > 0 {
		return fmt.Errorf(
			"credential query: %s differs only in case from the member the wire uses, so this verifier and a wallet would read different constraints",
			strings.Join(aliased, ", "))
	}
	return nil
}

func NewRawCredentialQuery(raw json.RawMessage) (CredentialQuery, error) {
	if !json.Valid(raw) {
		return CredentialQuery{}, fmt.Errorf("credential query: raw is not valid JSON")
	}
	// Refused here as well as on the decode paths. A request whose
	// constraint depends on the reader is not one to sign on anybody's
	// behalf, and allowing it here would also mean a query that works on
	// the replica that built it and nowhere else, since the decode paths
	// refuse to read it back.
	if err := checkRawConstraints(raw); err != nil {
		return CredentialQuery{}, err
	}
	query := CredentialQuery{Raw: append(json.RawMessage(nil), raw...)}
	query.adoptRawShadow()
	return query, nil
}

// adoptRawShadow fills in every modelled member the raw bytes can be read
// for, and reports the names of those that are present but unreadable.
//
// Raw is authoritative for the WIRE and for nothing else. Plenty of this
// stack reads the struct: UIInteraction copies ID into the authorization
// context's scopes and the response path matches a presentation back to
// it; matching reads Meta.TypeValues; Multiple and
// RequireCryptographicHolderBinding change what a response is allowed to
// contain. A query that arrived raw and kept the zero value for those was
// sent correctly and then judged against defaults nobody chose.
//
// Derived from the struct tags rather than written as a list of members,
// because the list is what goes stale - that is exactly how this started
// with only id and format. A member added to CredentialQuery is shadowed
// by the commit that adds it.
//
// Best effort per member: one that is absent, or of a shape this build
// cannot read, is left at its zero value rather than failing the whole
// decode. A query with a member this code has never seen is the reason
// these bytes are raw in the first place.
func (q *CredentialQuery) adoptRawShadow() (unreadable []string) {
	unreadable, _ = q.adoptRawShadowReporting()
	return unreadable
}

// adoptRawShadowReporting is adoptRawShadow, also reporting members that
// are the RIGHT JSON KIND for the model and still failed to decode.
//
// That distinction is the whole difference between the escape hatch and a
// bypass. "claims" as an object is a shape the model does not have - the
// rulebook's WIP example - and belongs in Raw. "claims" as an ARRAY whose
// entries the model rejects is an ordinary DCQL query that is simply
// invalid, and sending it to Raw would launder a decode error into a
// query that validates: ClaimQuery.UnmarshalJSON refuses an empty path,
// and such a query used to be refused outright.
// openItemMembers are members whose ITEMS are deliberately open, so an
// array this model cannot hold is an unmodelled shape rather than an
// ordinary invalid query.
//
// Only req. A circuit_zk request carries its arguments there, the
// rulebook is moving, and the vendored conformance set includes negative
// vectors - a numeric item id, array-valued params - that exist to be
// SENT. Without this they were accepted by NewRawCredentialQuery and
// then refused on the way back in: a request object is JSON-encoded into
// the HA cache and read by another node, so such a request could be
// published and then not reload anywhere but the node that built it.
//
// The other members keep the strict rule. claims, meta and format are
// what the SD-JWT and mdoc validation reads, and laundering a decode
// error there into Raw would turn an unreadable constraint into a query
// that validates because there is nothing left to judge.
var openItemMembers = map[string]bool{"req": true}

func (q *CredentialQuery) adoptRawShadowReporting() (unreadable, invalid []string) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(q.Raw, &members); err != nil {
		return nil, nil // not an object at all; nothing to shadow
	}

	type plain CredentialQuery // no methods, so no recursion
	shadow := plain{}
	value := reflect.ValueOf(&shadow).Elem()
	structure := value.Type()
	for i := range structure.NumField() {
		name, _, _ := strings.Cut(structure.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		encoded, present := members[name]
		if !present {
			continue
		}
		field := reflect.New(structure.Field(i).Type)
		if err := json.Unmarshal(encoded, field.Interface()); err != nil {
			unreadable = append(unreadable, name)
			if jsonKindMatches(structure.Field(i).Type, encoded) && !openItemMembers[name] {
				invalid = append(invalid, name)
			}
			continue
		}
		value.Field(i).Set(field.Elem())
	}

	raw := q.Raw
	*q = CredentialQuery(shadow)
	q.Raw = raw
	slices.Sort(unreadable)
	slices.Sort(invalid)
	return unreadable, invalid
}

// jsonKindMatches reports whether encoded is the JSON kind that target is
// modelled as - an array for a slice, an object for a struct or map, and
// so on.
//
// null matches everything, since unmarshalling it is a no-op whatever the
// destination, and an interface accepts any kind by definition.
func jsonKindMatches(target reflect.Type, encoded json.RawMessage) bool {
	trimmed := bytes.TrimLeft(encoded, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Interface:
		return true
	case reflect.Slice, reflect.Array:
		return trimmed[0] == '[' || trimmed[0] == 'n'
	case reflect.Struct, reflect.Map:
		return trimmed[0] == '{' || trimmed[0] == 'n'
	case reflect.String:
		return trimmed[0] == '"' || trimmed[0] == 'n'
	case reflect.Bool:
		return trimmed[0] == 't' || trimmed[0] == 'f' || trimmed[0] == 'n'
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return trimmed[0] == '-' || trimmed[0] == 'n' || (trimmed[0] >= '0' && trimmed[0] <= '9')
	}
	return false
}

type CredentialSetQuery struct {
	// Options REQUIRED A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array of identifiers which reference elements in credentials.
	Options [][]string `json:"options" yaml:"options" validate:"required,min=1,dive,required,min=1,dive,required"`

	// Required OPTIONAL. Spec default is true when omitted; nil pointer preserves that distinction from an explicit false.
	Required *bool `json:"required,omitempty" yaml:"required,omitempty"`
}

// IsRequired returns the effective value of Required, applying the OpenID4VP
// 1.0 §6.2 default (true) when the field was omitted.
func (q CredentialSetQuery) IsRequired() bool {
	if q.Required == nil {
		return true
	}
	return *q.Required
}

// AllowsMultiple returns the effective value of Multiple, applying the
// OpenID4VP 1.0 §6.1 default (false) when the member was omitted.
func (q CredentialQuery) AllowsMultiple() bool {
	return q.Multiple != nil && *q.Multiple
}

// RequiresCryptographicHolderBinding returns the effective value of
// RequireCryptographicHolderBinding, applying the OpenID4VP 1.0 §6.1
// default (true) when the field was omitted.
func (q CredentialQuery) RequiresCryptographicHolderBinding() bool {
	if q.RequireCryptographicHolderBinding == nil {
		return true
	}
	return *q.RequireCryptographicHolderBinding
}

// MetaQuery represents format-specific metadata constraints for credential queries.
// For SD-JWT VC format (dc+sd-jwt): use VCTValues
// For W3C VC format (ldp_vc): use TypeValues
type MetaQuery struct {
	// VCTValues for SD-JWT VC format (dc+sd-jwt).
	// A non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential.
	// All elements in the array MUST be valid type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc].
	// The Wallet MAY return Credentials that inherit from any of the specified types.
	VCTValues []string `json:"vct_values,omitempty" yaml:"vct_values,omitempty"`

	// TypeValues for W3C VC format (ldp_vc, jwt_vc_json).
	// A non-empty array of string arrays specifying the fully expanded types (IRIs) that the Verifier accepts.
	// Each top-level array specifies one alternative to match the fully expanded type values of the Verifiable Credential.
	// Each inner array specifies a set of fully expanded types that MUST be present in the credential's type property.
	TypeValues [][]string `json:"type_values,omitempty" yaml:"type_values,omitempty"`

	// DoctypeValue for ISO mdoc format (mso_mdoc) and ZK-mdoc format (mso_mdoc_zk).
	// String that specifies an allowed value for the doctype of the requested Verifiable Credential.
	DoctypeValue string `json:"doctype_value,omitempty" yaml:"doctype_value,omitempty"`

	// ZKSystemType for ZK-mdoc format (mso_mdoc_zk) only.
	// A non-empty array of ZK proof system/circuit variants the Verifier is
	// willing to accept (e.g. Longfellow circuits for different attribute
	// counts). See ZKSystemTypeSpec and dcql_zk.go.
	ZKSystemType []ZKSystemTypeSpec `json:"zk_system_type,omitempty" yaml:"zk_system_type,omitempty"`

	// PPIDContext for ZK-mdoc format (mso_mdoc_zk) only.
	// An optional verifier-supplied string that further scopes a requested
	// pairwise pseudonym (PPID) beyond the verifier's own identity - see
	// pkg/mdoc.ComputeZkVerifierContext.
	PPIDContext string `json:"ppid_context,omitempty" yaml:"ppid_context,omitempty"`
}

// VPFormatsSupported defines format-specific parameters for Verifier or Wallet metadata.
// Used in client_metadata and Wallet metadata to indicate supported formats and algorithms.
type VPFormatsSupported struct {
	// LDPVC is the configuration for W3C VC Data Integrity format (ldp_vc)
	LDPVC *LDPVCFormat `json:"ldp_vc,omitempty" yaml:"ldp_vc,omitempty"`

	// JWTVCJson is the configuration for JWT-based W3C VC format (jwt_vc_json)
	JWTVCJson *JWTVCFormat `json:"jwt_vc_json,omitempty" yaml:"jwt_vc_json,omitempty"`

	// SDJWT is the configuration for SD-JWT VC format (dc+sd-jwt)
	SDJWT *SDJWTVCFormat `json:"dc+sd-jwt,omitempty" yaml:"dc+sd-jwt,omitempty"`

	// MsoMdoc is the configuration for ISO mdoc format (mso_mdoc)
	MsoMdoc *MsoMdocFormat `json:"mso_mdoc,omitempty" yaml:"mso_mdoc,omitempty"`

	// CircuitZk is the configuration for zero-knowledge circuit
	// presentations (circuit_zk): which proof systems and circuits a proof
	// may come from.
	CircuitZk *CircuitZkFormat `json:"circuit_zk,omitempty" yaml:"circuit_zk,omitempty"`

	// Extra carries format entries this build does not know about,
	// flattened alongside the known ones - so a Verifier can offer a
	// format identifier that postdates this code.
	Extra map[string]any `json:"-" yaml:"-"`
}

// MarshalJSON flattens Extra alongside the known format entries.
func (v VPFormatsSupported) MarshalJSON() ([]byte, error) {
	type plain VPFormatsSupported
	return marshalWithExtra(plain(v), v.Extra, "vp_formats_supported")
}

// UnmarshalJSON collects unknown format entries into Extra.
func (v *VPFormatsSupported) UnmarshalJSON(data []byte) error {
	type plain VPFormatsSupported
	var known plain
	if err := decodeExact(data, &known); err != nil {
		return err
	}
	*v = VPFormatsSupported(known)
	extra, err := unknownMembers(data, "ldp_vc", "jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "circuit_zk")
	if err != nil {
		return err
	}
	v.Extra = extra
	return nil
}

// MarshalYAML flattens Extra alongside the known format entries.
//
// Needed as much as the JSON pair, and arguably more: this is the type
// verifier.preferred_vp_formats loads into, so the OPERATOR CONFIGURATION
// path is the one an unknown format identifier has to come in by. With
// JSON support alone the promise held only for metadata this build
// constructed itself, which is not where a format that postdates it
// arrives from.
func (v VPFormatsSupported) MarshalYAML() (any, error) {
	type plain VPFormatsSupported
	encoded, err := json.Marshal(plain(v))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := decodeExact(encoded, &m); err != nil {
		return nil, err
	}
	return mergeExtraYAML(m, v.Extra, declaredJSONKeys(reflect.TypeOf(VPFormatsSupported{})), "vp_formats_supported")
}

// UnmarshalYAML captures format entries this build does not model.
func (v *VPFormatsSupported) UnmarshalYAML(unmarshal func(any) error) error {
	type plain VPFormatsSupported
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("vp_formats_supported: %w", err)
	}
	*v = VPFormatsSupported(known)

	extra, err := yamlExtra(unmarshal, "vp_formats_supported",
		"ldp_vc", "jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "circuit_zk")
	if err != nil {
		return err
	}
	v.Extra = extra
	return nil
}

// LDPVCFormat defines format-specific parameters for W3C VC Data Integrity (ldp_vc).
type LDPVCFormat struct {
	// ProofTypeValues is a non-empty array containing identifiers of proof types supported.
	// If present, the proof type of the presented VC/VP MUST match one of the array values.
	ProofTypeValues []string `json:"proof_type_values,omitempty" yaml:"proof_type_values,omitempty" doc_example:"[\"DataIntegrityProof\", \"Ed25519Signature2020\"]"`

	// CryptosuiteValues is a non-empty array containing identifiers of crypto suites supported.
	// Used when one of the algorithms in ProofTypeValues supports multiple crypto suites.
	CryptosuiteValues []string `json:"cryptosuite_values,omitempty" yaml:"cryptosuite_values,omitempty" doc_example:"[\"ecdsa-rdfc-2019\", \"ecdsa-sd-2023\", \"eddsa-rdfc-2022\", \"bbs-2023\"]"`
}

// JWTVCFormat defines format-specific parameters for JWT-based W3C VC (jwt_vc_json).
type JWTVCFormat struct {
	// AlgValues is a non-empty array containing identifiers of cryptographic algorithms supported.
	// If present, the alg JOSE header of the presented VC/VP MUST match one of the array values.
	AlgValues []string `json:"alg_values,omitempty" yaml:"alg_values,omitempty"`
}

// SDJWTVCFormat defines format-specific parameters for IETF SD-JWT VC (dc+sd-jwt).
type SDJWTVCFormat struct {
	// SDJWTAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for the Issuer-signed JWT of an SD-JWT.
	SDJWTAlgValues []string `json:"sd-jwt_alg_values,omitempty" yaml:"sd-jwt_alg_values,omitempty"`

	// KBJWTAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for a Key Binding JWT (KB-JWT).
	KBJWTAlgValues []string `json:"kb-jwt_alg_values,omitempty" yaml:"kb-jwt_alg_values,omitempty"`
}

// MsoMdocFormat defines format-specific parameters for ISO mdoc (mso_mdoc).
type MsoMdocFormat struct {
	// IssuerAuthAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for IssuerAuth COSE signatures.
	IssuerAuthAlgValues []int `json:"issuerauth_alg_values,omitempty" yaml:"issuerauth_alg_values,omitempty"`

	// DeviceAuthAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for DeviceAuth COSE signatures or MACs.
	DeviceAuthAlgValues []int `json:"deviceauth_alg_values,omitempty" yaml:"deviceauth_alg_values,omitempty"`
}

type TrustedAuthority struct {
	// REQUIRED. A string uniquely identifying the type of information about the issuer trust framework. Types defined by this specification are listed below.
	Type string `json:"type" yaml:"type" validate:"required,oneof=aki etsi_tl openid_federation"`

	// REQUIRED. A non-empty array of strings, where each string (value) contains information specific to the used Trusted Authorities Query type that allows the identification of an issuer, a trust framework, or a federation that an issuer belongs to.
	Values []string `json:"values" yaml:"values" validate:"required,min=1"`
}

type ClaimQuery struct {
	// ID REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise.
	// A string identifying the particular claim. The value MUST be a non-empty string
	// consisting of alphanumeric, underscore (_), or hyphen (-) characters.
	// Within the particular claims array, the same id MUST NOT be present more than once.
	ID string `json:"-" yaml:"-"`

	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer
	// that specifies the path to a claim within the Credential, as defined in Section 7.
	// Elements are strings (object keys) or nil (representing null for array element access).
	Path []*string `json:"-" yaml:"-" validate:"required,min=1"`

	// Values OPTIONAL A non-empty array of strings, integers or boolean values that
	// specifies the expected values of the claim. If present, the Wallet SHOULD return
	// the claim only if the type and value of the claim both match exactly for at least
	// one of the elements in the array. See OpenID4VP Section 6.3 and 6.4.1.
	Values []any `json:"-" yaml:"-" validate:"omitnil,min=1"`
}

// MarshalJSON implements custom JSON marshaling for ClaimQuery.
// Nil path elements are serialized as JSON null (for DCQL array element access).
// A non-nil Values slice is validated against OpenID4VP §6.3; use nil to omit.
func (cq ClaimQuery) MarshalJSON() ([]byte, error) {
	if err := validateClaimPath(cq.Path); err != nil {
		return nil, err
	}
	if cq.Values != nil {
		if err := validateClaimValues(cq.Values, true); err != nil {
			return nil, err
		}
	}
	path := make([]any, len(cq.Path))
	for i, p := range cq.Path {
		if p == nil {
			path[i] = nil
		} else {
			path[i] = *p
		}
	}
	type wire struct {
		ID     string `json:"id,omitempty"`
		Path   []any  `json:"path"`
		Values []any  `json:"values,omitempty"`
	}
	return json.Marshal(wire{ID: cq.ID, Path: path, Values: cq.Values})
}

// UnmarshalJSON implements custom JSON unmarshaling for ClaimQuery.
// JSON null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error (Go's json package rejects them for *string).
func (cq *ClaimQuery) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID     string          `json:"id"`
		Path   []*string       `json:"path"`
		Values json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	var values []any
	if len(raw.Values) > 0 {
		if bytes.Equal(bytes.TrimSpace(raw.Values), []byte("null")) {
			return fmt.Errorf(`claim "values" must not be null`)
		}
		// decodeExact, not json.Unmarshal: it keeps numbers as their
		// literals. A plain decode makes every value a float64, so a
		// legitimate 9007199254740993 came back as 9007199254740992 and
		// was then rejected for being outside the safe integer range -
		// which made a stored context carrying one UNREADABLE once the
		// exact JSON copy became the preferred representation. Saved
		// fine, failed on the way back.
		if err := decodeExact(raw.Values, &values); err != nil {
			return fmt.Errorf(`claim "values" must be an array of strings, integers, or booleans: %w`, err)
		}
	}
	if err := validateClaimValues(values, len(raw.Values) > 0); err != nil {
		return err
	}
	cq.ID = raw.ID
	cq.Path = raw.Path
	cq.Values = values
	return nil
}

// MarshalYAML implements gopkg.in/yaml.v2's Marshaler interface for ClaimQuery.
// Mirrors MarshalJSON: the ClaimQuery fields carry yaml:"-" tags to route
// through this method, so without it yaml.Marshal would emit an empty mapping
// and drop id/path/values.
func (cq ClaimQuery) MarshalYAML() (any, error) {
	if err := validateClaimPath(cq.Path); err != nil {
		return nil, err
	}
	if cq.Values != nil {
		if err := validateClaimValues(cq.Values, true); err != nil {
			return nil, err
		}
	}
	path := make([]any, len(cq.Path))
	for i, p := range cq.Path {
		if p == nil {
			path[i] = nil
		} else {
			path[i] = *p
		}
	}
	return struct {
		ID     string `yaml:"id,omitempty"`
		Path   []any  `yaml:"path"`
		Values []any  `yaml:"values,omitempty"`
	}{ID: cq.ID, Path: path, Values: cq.Values}, nil
}

// UnmarshalYAML implements custom YAML unmarshaling for ClaimQuery.
// YAML null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error.
func (cq *ClaimQuery) UnmarshalYAML(unmarshal func(any) error) error {
	var raw struct {
		ID   string    `yaml:"id"`
		Path []*string `yaml:"path"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	// Second pass into a generic map so we can distinguish an absent "values"
	// key from an explicit YAML null — yaml.v2 unmarshals both into the same
	// zero value when the target field type is []any.
	var check map[string]any
	if err := unmarshal(&check); err != nil {
		return err
	}
	var values []any
	rawValues, present := check["values"]
	if present {
		if rawValues == nil {
			return fmt.Errorf(`claim "values" must not be null`)
		}
		arr, ok := rawValues.([]any)
		if !ok {
			return fmt.Errorf(`claim "values" must be an array of strings, integers, or booleans`)
		}
		values = arr
	}
	if err := validateClaimValues(values, present); err != nil {
		return err
	}
	cq.ID = raw.ID
	cq.Path = raw.Path
	cq.Values = values
	return nil
}

// validateClaimPath checks that the path is non-empty and that non-nil elements are not empty strings.
// Nil elements are valid (they represent JSON null for array element access).
func validateClaimPath(path []*string) error {
	if len(path) == 0 {
		return fmt.Errorf("claim path must not be empty")
	}
	for i, p := range path {
		if p != nil && *p == "" {
			return fmt.Errorf("claim path element at index %d must not be empty", i)
		}
	}
	return nil
}

// validateClaimValues enforces the OpenID4VP Section 6.3 rule that "values" must be
// a non-empty array of strings, integers, or booleans when present. JSON decoding
// widens numeric values into float64, so integer-valued floats are accepted — but
// only within the IEEE-754 safe integer range (±(2^53-1)); larger magnitudes may
// have been silently rounded by the decoder and can no longer be trusted to
// "match exactly" per the spec.
// present tells the validator that the key existed on the wire so an empty array
// can be rejected (an absent key is legal — "values" is OPTIONAL).
func validateClaimValues(values []any, present bool) error {
	if !present {
		return nil
	}
	if len(values) == 0 {
		return fmt.Errorf(`claim "values" must not be empty when present`)
	}
	for i, v := range values {
		switch t := v.(type) {
		case string, bool, int, int32, int64, uint, uint32, uint64:
		case json.Number:
			// Judged AS the literal, with no float64 on the way. The
			// float arms below stop at 2^53-1 because that is where a
			// float64 stops being exact; a literal has no such limit, so
			// imposing one here would be this validator inventing a rule
			// the specification does not have - and rejecting the very
			// values the exact-JSON copy exists to preserve.
			if !isIntegralNumber(t.String()) {
				return fmt.Errorf("claim values[%d] must be a string, integer, or boolean", i)
			}
		case float32:
			if err := checkIntegralFloat(float64(t), i); err != nil {
				return err
			}
		case float64:
			if err := checkIntegralFloat(t, i); err != nil {
				return err
			}
		default:
			return fmt.Errorf("claim values[%d] must be a string, integer, or boolean", i)
		}
	}
	return nil
}

// isIntegralNumber reports whether a JSON number literal denotes an
// integer - its VALUE, not its spelling.
//
// 10, 10.0 and 1e1 are all the integer ten, and a validator that accepts
// only the first changes what an ordinary SD-JWT or mdoc query may say.
// An earlier version of this tested the spelling and did exactly that.
//
// Decided on the digits rather than by parsing to a number, because
// parsing is what this exists to avoid: a float64 cannot hold
// 9007199254740993, and that value is the reason the exact copy exists.
//
// A literal is digits x 10^(exp - len(frac)). Shift the point right by
// that exponent: if it lands at or past the end of the digits the value
// is an integer, and if it lands inside them the digits it would cut
// have to be zeros.
func isIntegralNumber(literal string) bool {
	mantissa, exponent := literal, 0
	if i := strings.IndexAny(literal, "eE"); i >= 0 {
		parsed, err := strconv.Atoi(literal[i+1:])
		if err != nil {
			return false
		}
		mantissa, exponent = literal[:i], parsed
	}
	mantissa = strings.TrimPrefix(strings.TrimPrefix(mantissa, "-"), "+")

	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := whole + fraction
	if digits == "" {
		return false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	// Zero is an integer however it is spelled, including 0e-5.
	if strings.Trim(digits, "0") == "" {
		return true
	}

	// A nonzero value whose every significant digit falls to the right of
	// the point is not an integer. Deciding that on the exponent alone
	// keeps the arithmetic below away from the ends of the int range: a
	// literal may carry an exponent as extreme as math.MinInt64, where
	// negating the shift wraps round to a negative cut that panics the
	// slice, and subtracting the fraction length wraps the other way and
	// reports a fraction as integral.
	if exponent <= len(fraction)-len(digits) {
		return false
	}
	shift := exponent - len(fraction)
	if shift >= 0 {
		return true
	}
	return strings.Trim(digits[len(digits)+shift:], "0") == ""
}

func checkIntegralFloat(f float64, i int) error {
	const maxSafeInt = float64(1<<53 - 1)
	if math.IsNaN(f) || math.IsInf(f, 0) || f < -maxSafeInt || f > maxSafeInt || f != math.Trunc(f) {
		return fmt.Errorf("claim values[%d] must be a string, integer, or boolean", i)
	}
	return nil
}

// StringPath creates a []*string path from string arguments.
// This is a convenience for constructing ClaimQuery paths.
func StringPath(parts ...string) []*string {
	path := make([]*string, len(parts))
	for i := range parts {
		s := parts[i]
		path[i] = &s
	}
	return path
}

// ArrayElementPath creates a []*string path ending with nil (null) for array element access.
// Example: ArrayElementPath("nationalities") → ["nationalities", null]
func ArrayElementPath(parts ...string) []*string {
	path := make([]*string, len(parts)+1)
	for i := range parts {
		s := parts[i]
		path[i] = &s
	}
	path[len(parts)] = nil // null for array element access
	return path
}

// Credential format identifiers as defined in OpenID4VP Appendix B.
// Note: FormatLdpVC is defined in vc20_handler.go (vc20 build tag)
const (
	// FormatJwtVCJson is the format identifier for JWT-based W3C VC without JSON-LD.
	FormatJwtVCJson = "jwt_vc_json"
	// FormatSDJWTVC is the format identifier for IETF SD-JWT VC.
	FormatSDJWTVC = "dc+sd-jwt"
	// FormatMsoMdoc is the format identifier for ISO mdoc.
	FormatMsoMdoc = "mso_mdoc"
	// FormatLdpVCDCQL is the format identifier for W3C VC Data Integrity (used in DCQL).
	// Note: This duplicates FormatLdpVC from vc20_handler.go but is needed for non-vc20 builds.
	FormatLdpVCDCQL = "ldp_vc"

	// BaseVCTypeIRI is the expanded form of the type every W3C VC carries.
	// A type_values alternative naming only this constrains nothing.
	BaseVCTypeIRI = "https://www.w3.org/2018/credentials#VerifiableCredential"
	// FormatVCLDJSON is the other spelling this repo issues W3C VC Data
	// Integrity under - see handlers_issuer.go, which routes it to issueVC20
	// alongside ldp_vc.
	FormatVCLDJSON = "vc+ld+json"
)

// IsW3CVCFormatIdentifier returns true if the format identifier is a W3C
// Verifiable Credential format (ldp_vc, vc+ld+json or jwt_vc_json).
//
// vc+ld+json belongs here because this repo issues it as one: handlers_issuer.go
// routes it to issueVC20 alongside ldp_vc. Leaving it out meant a query in that
// format skipped the type_values requirement in ValidateCredentialQuery that
// the other two are held to, so an unconstrained W3C query passed validation.
func IsW3CVCFormatIdentifier(format string) bool {
	return format == FormatLdpVCDCQL || format == FormatVCLDJSON || format == FormatJwtVCJson
}

// IsSDJWTFormatIdentifier returns true if the format identifier is SD-JWT VC format.
// Note: This is different from sdjwtvc.IsSDJWTFormat which checks the actual token format.
func IsSDJWTFormatIdentifier(format string) bool {
	return format == FormatSDJWTVC
}

// IsMdocFormat returns true if the format is ISO mdoc format.
func IsMdocFormat(format string) bool {
	return format == FormatMsoMdoc
}

// MatchTypeValues checks if a credential's types match any of the type_values alternatives.
// credentialTypes should be the fully expanded type IRIs from the credential.
// typeValues is the query's type_values constraint (array of string arrays).
// Returns true if the credential matches at least one of the alternatives.
func MatchTypeValues(credentialTypes []string, typeValues [][]string) bool {
	if len(typeValues) == 0 {
		return true // No constraints
	}

	// Check each alternative (outer array)
	for _, requiredTypes := range typeValues {
		if containsAll(credentialTypes, requiredTypes) {
			return true
		}
	}
	return false
}

// containsAll checks if all requiredTypes are present in credentialTypes.
func containsAll(credentialTypes []string, requiredTypes []string) bool {
	typeSet := make(map[string]bool)
	for _, t := range credentialTypes {
		typeSet[t] = true
	}

	for _, required := range requiredTypes {
		if !typeSet[required] {
			return false
		}
	}
	return true
}

// MatchCryptosuite checks if a cryptosuite is supported by the format configuration.
// Returns true if cryptosuiteValues is empty (no constraint) or contains the cryptosuite.
func MatchCryptosuite(cryptosuite string, cryptosuiteValues []string) bool {
	if len(cryptosuiteValues) == 0 {
		return true
	}
	return slices.Contains(cryptosuiteValues, cryptosuite)
}

// MatchProofType checks if a proof type is supported by the format configuration.
// Returns true if proofTypeValues is empty (no constraint) or contains the proofType.
func MatchProofType(proofType string, proofTypeValues []string) bool {
	if len(proofTypeValues) == 0 {
		return true
	}
	return slices.Contains(proofTypeValues, proofType)
}

// TrustedAuthorityType constants per OpenID4VP spec Section 6.1.1
const (
	// TrustedAuthorityTypeAKI is for Authority Key Identifier matching.
	// Value is base64url-encoded KeyIdentifier from AuthorityKeyIdentifier.
	TrustedAuthorityTypeAKI = "aki"

	// TrustedAuthorityTypeETSI is for ETSI Trusted List matching.
	// Value is the URL of the Trusted List (e.g., https://lotl.example.com).
	TrustedAuthorityTypeETSI = "etsi_tl"

	// TrustedAuthorityTypeOpenIDFederation is for OpenID Federation matching.
	// Value is the Entity Identifier of the Trust Anchor.
	TrustedAuthorityTypeOpenIDFederation = "openid_federation"
)

// TrustedAuthorityMatcher provides methods for matching credentials against trusted authorities.
// Implementations should integrate with trust frameworks (go-trust, ETSI TL, etc.).
type TrustedAuthorityMatcher interface {
	// MatchAKI checks if a credential's certificate chain contains a certificate
	// with the given Authority Key Identifier (base64url-encoded).
	MatchAKI(credentialCertChain [][]byte, aki string) bool

	// MatchETSI checks if a credential's issuer is present in the ETSI Trusted List.
	// The tlURL is the URL of the Trusted List or List of Trusted Lists.
	MatchETSI(credentialCertChain [][]byte, tlURL string) bool

	// MatchOpenIDFederation checks if a credential's issuer is part of an OpenID Federation
	// with the given Trust Anchor entity identifier.
	MatchOpenIDFederation(issuer string, trustAnchorEntityID string) bool
}

// MatchTrustedAuthorities checks if a credential matches any of the trusted authorities constraints.
// Returns true if trustedAuthorities is empty (no constraint) or the credential matches at least one.
// The matcher parameter provides the actual trust verification implementation.
// If matcher is nil, returns true (no validation performed).
func MatchTrustedAuthorities(
	trustedAuthorities []TrustedAuthority,
	credentialCertChain [][]byte,
	issuer string,
	matcher TrustedAuthorityMatcher,
) bool {
	// No constraints - accept all
	if len(trustedAuthorities) == 0 {
		return true
	}

	// No matcher provided - skip validation (trust decision made elsewhere)
	if matcher == nil {
		return true
	}

	// Check if credential matches ANY of the trusted authorities
	for _, ta := range trustedAuthorities {
		for _, value := range ta.Values {
			switch ta.Type {
			case TrustedAuthorityTypeAKI:
				if matcher.MatchAKI(credentialCertChain, value) {
					return true
				}
			case TrustedAuthorityTypeETSI:
				if matcher.MatchETSI(credentialCertChain, value) {
					return true
				}
			case TrustedAuthorityTypeOpenIDFederation:
				if matcher.MatchOpenIDFederation(issuer, value) {
					return true
				}
			}
		}
	}

	return false
}

// NewTrustedAuthorityAKI creates a TrustedAuthority for Authority Key Identifier matching.
func NewTrustedAuthorityAKI(akiValues ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeAKI,
		Values: akiValues,
	}
}

// NewTrustedAuthorityETSI creates a TrustedAuthority for ETSI Trusted List matching.
func NewTrustedAuthorityETSI(tlURLs ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeETSI,
		Values: tlURLs,
	}
}

// NewTrustedAuthorityOpenIDFederation creates a TrustedAuthority for OpenID Federation matching.
func NewTrustedAuthorityOpenIDFederation(trustAnchors ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeOpenIDFederation,
		Values: trustAnchors,
	}
}

// ValidateCredentialQuery validates that a CredentialQuery has the required fields
// for the specified format.
func ValidateCredentialQuery(query CredentialQuery) error {
	// A raw query is judged by its own bytes, not by the empty struct the
	// failed typed decode left behind.
	//
	// The escape hatch is for a member whose SHAPE this build does not
	// model; it is not a way around the constraint rules, and it is not
	// specific to one format. Reading format and meta back out of the raw
	// bytes keeps both true at once: an SD-JWT query with no vct_values is
	// still refused here even though it arrived raw, and a circuit_zk one
	// still falls to the permissive default below, as every format this
	// build does not constrain does.
	if query.Raw != nil {
		if !json.Valid(query.Raw) {
			return &DCQLValidationError{
				Field:   "raw",
				Message: "a raw credential query must be valid JSON",
			}
		}
		// An UNREADABLE meta is judged as an EMPTY one, not waved through.
		//
		// "Cannot read the constraint" and "there is no constraint" are
		// the same thing to everyone downstream: either way nothing here
		// has established what the request is limited to. Returning nil
		// on the first and refusing the second would let
		// {"format":"vc+sd-jwt","meta":"not an object"} be signed and
		// served with no vct_values - the very case this check exists for,
		// reached by making the member harder to read rather than by
		// omitting it.
		//
		// Substituting the zero value rather than naming the formats that
		// have rules keeps the two in step by construction: a zero
		// MetaQuery satisfies no constraint rule in the switch below, and
		// passes the permissive default exactly where there is no rule to
		// fail. A format that grows one later is covered without anything
		// here being updated.
		// Re-read from the BYTES rather than trusting the struct's
		// shadow: that is populated by UnmarshalJSON, and a query built in
		// code - CredentialQuery{Raw: ...}, which is how the escape hatch
		// is meant to be used directly - carries none of it.
		shadow := CredentialQuery{Raw: query.Raw}
		unreadable := shadow.adoptRawShadow()
		if !json.Valid(query.Raw) || !isJSONObject(query.Raw) {
			// A credential query that is not an object carries no members
			// at all, which is the strongest form of "the constraint
			// cannot be read" rather than a separate case.
			unreadable = append(unreadable, "meta")
		}
		query = shadow
		query.Raw = nil
		if slices.Contains(unreadable, "meta") {
			if err := ValidateCredentialQuery(query); err != nil {
				// Reported as what it is. "vct_values is required" would
				// send an operator looking for a member that may well be
				// in the bytes, inside the meta this could not read.
				return &DCQLValidationError{
					Field:   "meta",
					Message: fmt.Sprintf("meta is a shape this build cannot read, so the %s constraint it would have to satisfy cannot be established: %v", formatOrDefault(query.Format), err),
				}
			}
			return nil
		}
	}
	switch query.Format {
	// Not FormatJwtVCJson: UIInteraction calls this on the live ingress, and
	// the rest of the stack refuses that format - nothing issues it and the
	// verifier reads a compact JWT-VC as SD-JWT. Accepting it here would let
	// it in through the one door still open.
	case FormatLdpVCDCQL, FormatVCLDJSON:
		// W3C VC format requires type_values, and every alternative must
		// actually constrain: MatchTypeValues reads an empty alternative as
		// satisfied by any credential, and one satisfied alternative answers
		// the whole constraint - so [[]] is an unconstrained request wearing
		// a constraint's shape.
		for i, alternative := range query.Meta.TypeValues {
			// EVERY member has to be a fully expanded IRI, not just one.
			// type_values are matched as expanded IRIs (OpenID4VP 1.0
			// B.3.2), the verifier drops relative ones from the credential
			// side for the same reason, and MatchTypeValues requires a
			// credential to carry ALL of an alternative's types - so an
			// alternative holding one good IRI and one compact term
			// validates, is sent, and can never match. A query that cannot
			// be satisfied is not a constraint, it is an outage wearing a
			// constraint's shape. Config load refuses these too; this is
			// the path templates and API callers arrive by.
			for j, member := range alternative {
				// Strict: see credential.IsAbsoluteIRI. A colon alone does
				// not make a reference absolute.
				if member != "" && credential.IsAbsoluteIRI(member) {
					continue
				}
				return &DCQLValidationError{
					Field:   fmt.Sprintf("meta.type_values[%d][%d]", i, j),
					Message: fmt.Sprintf("type_values members are matched as fully expanded IRIs (OpenID4VP 1.0 B.3.2), so %q can never match a credential", member),
				}
			}
			// And at least one of them has to NARROW. Base-only is the
			// same defect as empty, one step along: every W3C credential
			// carries VerifiableCredential, so an alternative naming only
			// it is satisfied by all of them. The config path
			// (CredentialMetadata.w3cTypeValues) already refuses that; an
			// API-supplied query has to be held to the same rule, or the
			// request over-discloses without ever looking unconstrained.
			narrowing := slices.ContainsFunc(alternative, func(t string) bool {
				return t != BaseVCTypeIRI
			})
			if !narrowing {
				return &DCQLValidationError{
					Field:   fmt.Sprintf("meta.type_values[%d]", i),
					Message: "each type_values alternative must name at least one fully expanded IRI beyond " + BaseVCTypeIRI + "; a base-only alternative matches every W3C credential",
				}
			}
		}
		if len(query.Meta.TypeValues) == 0 {
			return &DCQLValidationError{
				Field:   "meta.type_values",
				Message: "type_values is required for W3C VC format",
			}
		}
	// "vc+sd-jwt" is the legacy spelling this repo still issues, and "" is
	// Format's own default. DCQLMetaQuery, the UI builder and the verifier's
	// format check all classify both as SD-JWT; leaving either to the
	// permissive default below meant such a query passed validation with no
	// constraint at all. Every place that decides what a format MEANS has to
	// agree with every place that decides whether it is CONSTRAINED.
	case FormatSDJWTVC, "vc+sd-jwt", "":
		// SD-JWT VC format requires vct_values
		if len(query.Meta.VCTValues) == 0 {
			return &DCQLValidationError{
				Field:   "meta.vct_values",
				Message: "vct_values is required for SD-JWT VC format",
			}
		}
	case FormatMsoMdoc:
		// ISO mdoc requires doctype_value
		if query.Meta.DoctypeValue == "" {
			return &DCQLValidationError{
				Field:   "meta.doctype_value",
				Message: "doctype_value is required for ISO mdoc format",
			}
		}
	case FormatMsoMdocZk:
		return validateMsoMdocZkQuery(query)
	// Refused explicitly, NOT left to the default below. Both are advertised
	// in issuer metadata and neither is requestable: nothing issues them, and
	// the verifier reads a compact JWT-VC as SD-JWT, so it would verify one
	// under the wrong credential model. UIInteraction validates here on the
	// live ingress, and "allow but do not validate" would wave them through
	// with no constraint at all.
	case FormatJwtVCJson, "jwt_vc_json-ld":
		return &DCQLValidationError{
			Field:   "format",
			Message: fmt.Sprintf("format %q is advertised but not requestable: nothing issues it and there is no verification path for it", query.Format),
		}
	default:
		// Unknown format - allow but don't validate
	}
	return nil
}

// isJSONObject reports whether data is a JSON object, which is what a
// credential query has to be before any member can be read from it.
func isJSONObject(data []byte) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil
}

// formatOrDefault names a format for an error message, spelling out the
// empty one rather than printing "" - which reads as a missing format
// when it is in fact the SD-JWT default.
func formatOrDefault(format string) string {
	if format == "" {
		return FormatSDJWTVC + " (the default for an absent format)"
	}
	return format
}

// validateMsoMdocZkQuery validates the ZK-mdoc (mso_mdoc_zk)-specific
// fields of a CredentialQuery, split out of ValidateCredentialQuery to
// keep that function's per-format switch flat (this format alone needs a
// nested per-entry loop over zk_system_type, unlike every other format).
func validateMsoMdocZkQuery(query CredentialQuery) error {
	// ZK-mdoc requires doctype_value, same as plain mso_mdoc.
	if query.Meta.DoctypeValue == "" {
		return &DCQLValidationError{
			Field:   "meta.doctype_value",
			Message: "doctype_value is required for ZK-mdoc format",
		}
	}
	// ...plus a non-empty zk_system_type array declaring which ZK
	// systems/circuits the verifier accepts, each entry of which must
	// itself carry the "id"/"system" fields ZKSystemTypeSpec requires
	// (matching/circuit resolution depends on both being present - see
	// MatchZKSystemType and pkg/mdoc/zkcircuit.Client.FetchCircuit).
	if len(query.Meta.ZKSystemType) == 0 {
		return &DCQLValidationError{
			Field:   "meta.zk_system_type",
			Message: "zk_system_type is required for ZK-mdoc format",
		}
	}
	for i, spec := range query.Meta.ZKSystemType {
		if spec.ID == "" {
			return &DCQLValidationError{
				Field:   fmt.Sprintf("meta.zk_system_type[%d].id", i),
				Message: "id is required for each zk_system_type entry",
			}
		}
		if spec.System == "" {
			return &DCQLValidationError{
				Field:   fmt.Sprintf("meta.zk_system_type[%d].system", i),
				Message: "system is required for each zk_system_type entry",
			}
		}
	}
	return nil
}

// DCQLValidationError represents a validation error in a DCQL query.
type DCQLValidationError struct {
	Field   string
	Message string
}

func (e *DCQLValidationError) Error() string {
	return "DCQL validation error on " + e.Field + ": " + e.Message
}

// NewVC20CredentialQuery creates a new CredentialQuery for W3C VC 2.0 Data Integrity format.
// typeValues should be an array of type alternatives, where each alternative is an array
// of fully expanded type IRIs that must all be present in the credential.
func NewVC20CredentialQuery(id string, typeValues [][]string, claims []ClaimQuery) CredentialQuery {
	return CredentialQuery{
		ID:     id,
		Format: FormatLdpVCDCQL,
		Meta: MetaQuery{
			TypeValues: typeValues,
		},
		Claims:                            claims,
		RequireCryptographicHolderBinding: new(true),
	}
}

// NewVC20VPFormatsSupported creates a VPFormatsSupported configuration for W3C VC 2.0
// Data Integrity format with the specified cryptosuites.
func NewVC20VPFormatsSupported(cryptosuites []string) VPFormatsSupported {
	return VPFormatsSupported{
		LDPVC: &LDPVCFormat{
			ProofTypeValues:   []string{"DataIntegrityProof"},
			CryptosuiteValues: cryptosuites,
		},
	}
}
