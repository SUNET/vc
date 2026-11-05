package openid4vp

import (
	"errors"
	"reflect"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// The CBOR reader for a ZkpPresentation, strict in the four ways rule
// 3 names - and only those.
//
// It is NOT a canonicality check: integers and lengths in non-shortest
// form are accepted on purpose. A prover that encodes a length the
// long way has produced a different encoding of the same value, and
// refusing it would refuse a presentation the rulebook permits.
//
// What IS refused is anything that would let two readers disagree
// about what they read: an indefinite length (which a streaming reader
// and a buffering one chunk differently), a repeated map key (which a
// map-typed decode silently collapses, so whichever value survives is
// the wallet's choice and not this verifier's), bytes after the item,
// and the ordinary malformed cases.
var (
	zkpCBORModeOnce sync.Once
	zkpCBORMode     cbor.DecMode
	zkpCBORStrict   cbor.DecMode
)

func initZkpCBORModes() {
	// The lenient-on-indefinite mode. Everything else is strict, so a
	// failure here is malformed, a duplicate key, or bad UTF-8.
	lenient, err := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthAllowed,
		MaxNestedLevels: maxCBORNestingLevels,
		UTF8:            cbor.UTF8RejectInvalid,
		DefaultMapType:  reflect.TypeOf(map[any]any(nil)),
	}.DecMode()
	if err != nil {
		panic("openid4vp: zkp_req CBOR mode: " + err.Error())
	}
	zkpCBORMode = lenient

	// The same, refusing indefinite lengths. Running both is what
	// separates "indefinite length" from "malformed" without matching
	// on a library's message text.
	strict, err := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		MaxNestedLevels: maxCBORNestingLevels,
		UTF8:            cbor.UTF8RejectInvalid,
		DefaultMapType:  reflect.TypeOf(map[any]any(nil)),
	}.DecMode()
	if err != nil {
		panic("openid4vp: zkp_req strict CBOR mode: " + err.Error())
	}
	zkpCBORStrict = strict
}

func zkpCBOR() (cbor.DecMode, cbor.DecMode) {
	zkpCBORModeOnce.Do(initZkpCBORModes)
	return zkpCBORMode, zkpCBORStrict
}

// decodeZkpPresentationCBOR reads the presentation map, with each
// member left raw so its own type error can be reported precisely.
func decodeZkpPresentationCBOR(data []byte) (map[string]cbor.RawMessage, error) {
	lenient, strict := zkpCBOR()

	// Indefinite length first: a presentation that is indefinite AND
	// malformed is reported as indefinite, which is the more specific
	// statement about what the prover did.
	var probe any
	if _, err := strict.UnmarshalFirst(data, &probe); err != nil {
		if _, lenientErr := lenient.UnmarshalFirst(data, &probe); lenientErr == nil {
			return nil, refuse(ReasonCBORIndefiniteLength, "the presentation uses an indefinite length")
		}
	}

	// Into RawMessage, not `any`: a RawMessage keeps every value as
	// bytes, so no tag is ever interpreted here. Decoding into `any`
	// turns tag 0 into a time.Time and fails on a date that is merely
	// WRONG - reporting an unparseable presentation where the right
	// answer is proof_time_form, three rules later.
	var whole cbor.RawMessage
	rest, err := lenient.UnmarshalFirst(data, &whole)
	if err != nil {
		return nil, classifyCBORError(err)
	}
	if len(rest) > 0 {
		return nil, refuse(ReasonCBORTrailingBytes, "%d bytes after the presentation", len(rest))
	}
	// Duplicate keys and key types, at every level, now that the item
	// is known to be one well-formed value.
	if err := refuseDuplicateCBORKeys(lenient, whole, 0); err != nil {
		return nil, err
	}

	// The shape: a map whose keys are all text.
	//
	// The major type BEFORE the decode, because CBOR null decodes
	// into a map as nil without error - which would arrive below as a
	// map with no members and be reported as a missing one.
	if !isCBORMap(whole) {
		return nil, refuse(ReasonPresentationNotMap, "the presentation is not a map")
	}
	var raw map[any]cbor.RawMessage
	if err := lenient.Unmarshal(whole, &raw); err != nil {
		return nil, refuse(ReasonPresentationNotMap, "the presentation is not a map")
	}
	members := make(map[string]cbor.RawMessage, len(raw))
	for key, value := range raw {
		name, isText := key.(string)
		if !isText {
			return nil, refuse(ReasonPresentationKeyNotText, "a presentation key is %T, not a text string", key)
		}
		members[name] = value
	}
	return members, nil
}

// cborResultsMap reads the results map, keeping each value raw and
// insisting every key is text.
func cborResultsMap(raw cbor.RawMessage) (map[string]cbor.RawMessage, error) {
	if isCBORNull(raw) {
		return nil, refuse(ReasonPresentationMemberWrongType, "\"results\" is null")
	}
	lenient, _ := zkpCBOR()
	var byAny map[any]cbor.RawMessage
	if err := lenient.Unmarshal(raw, &byAny); err != nil {
		var badKey *cbor.InvalidMapKeyTypeError
		if errors.As(err, &badKey) {
			return nil, refuse(ReasonResultKeyNotText, "%v", err)
		}
		return nil, refuse(ReasonPresentationMemberWrongType, "\"results\" is not a map")
	}
	results := make(map[string]cbor.RawMessage, len(byAny))
	for key, value := range byAny {
		name, isText := key.(string)
		if !isText {
			return nil, refuse(ReasonResultKeyNotText, "a results key is %T, not a text string", key)
		}
		results[name] = value
	}
	return results, nil
}

// decodeProofTimeTDate reads proof_time as the tag-0 text string it
// has to be, and returns the text unchanged.
//
// The TEXT, not a time.Time: the circuit takes those 20 bytes as a
// public input, so what matters is the spelling the prover used and
// not the instant it denotes.
func decodeProofTimeTDate(raw cbor.RawMessage) (string, error) {
	if isCBORNull(raw) {
		return "", refuse(ReasonProofTimeNotTDate, "proof_time is null")
	}
	lenient, _ := zkpCBOR()
	var tag cbor.RawTag
	if err := lenient.Unmarshal(raw, &tag); err != nil {
		return "", refuse(ReasonProofTimeNotTDate, "proof_time is not a tagged value")
	}
	if tag.Number != 0 {
		return "", refuse(ReasonProofTimeNotTDate, "proof_time carries tag %d, not tag 0", tag.Number)
	}
	var text string
	if err := lenient.Unmarshal(tag.Content, &text); err != nil {
		return "", refuse(ReasonProofTimeNotTDate, "the tag-0 content is not a text string")
	}
	return text, nil
}

// classifyCBORError maps a decode failure to the reason code the
// shared vocabulary uses for it.
func classifyCBORError(err error) error {
	var dup *cbor.DupMapKeyError
	if errors.As(err, &dup) {
		return refuse(ReasonCBORDuplicateKey, "%v", err)
	}
	var badTag *cbor.InadmissibleTagContentTypeError
	if errors.As(err, &badTag) {
		// The reader validates a tag's content type while checking
		// well-formedness, so a tag 0 around anything but a text
		// string fails here rather than at rule 8. proof_time is the
		// only tagged member a ZkpPresentation has, and the error
		// names tag 0 itself, so this is that rule's refusal arriving
		// early rather than a malformed item.
		return refuse(ReasonProofTimeNotTDate, "%v", err)
	}
	return refuse(ReasonCBORMalformed, "%v", err)
}

// refuseDuplicateCBORKeys walks the item, refusing a map that repeats
// a key or carries a non-text key, at ANY level.
//
// Done by hand because the values stay raw: decoding the whole item
// into `any` would enforce duplicates for free but would also
// interpret tags, which is exactly what must not happen before
// proof_time is reached.
//
// Keys are compared structurally - the decoder refuses a repeat even
// when the two values are identical - because a reader that collapsed
// them would be choosing which one to believe.
func refuseDuplicateCBORKeys(mode cbor.DecMode, raw cbor.RawMessage, depth int) error {
	if depth > maxCBORNestingLevels {
		return refuse(ReasonCBORMalformed, "nesting deeper than %d levels", maxCBORNestingLevels)
	}
	switch {
	case isCBORMap(raw):
		var asMap map[any]cbor.RawMessage
		if err := mode.Unmarshal(raw, &asMap); err != nil {
			var badKey *cbor.InvalidMapKeyTypeError
			if errors.As(err, &badKey) {
				// An unhashable key - an array or a map used as one.
				return refuse(ReasonPresentationKeyNotText, "%v", err)
			}
			return classifyCBORError(err)
		}
		for _, value := range asMap {
			if err := refuseDuplicateCBORKeys(mode, value, depth+1); err != nil {
				return err
			}
		}
	case isCBORArray(raw):
		var items []cbor.RawMessage
		if err := mode.Unmarshal(raw, &items); err != nil {
			return classifyCBORError(err)
		}
		for _, item := range items {
			if err := refuseDuplicateCBORKeys(mode, item, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// isCBORMap and isCBORArray read the major type off the head byte,
// without decoding the item.
func isCBORMap(raw cbor.RawMessage) bool   { return len(raw) > 0 && raw[0]>>5 == 5 }
func isCBORArray(raw cbor.RawMessage) bool { return len(raw) > 0 && raw[0]>>5 == 4 }
