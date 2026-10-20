package openid4vp

import (
	"bytes"
	"encoding/json"
	"io"
)

// Repeated JSON member names have to be judged on the RAW TEXT.
//
// A decoded object cannot represent them: every JSON decoder keeps one
// of the values and discards the other silently. So a response
// carrying two values for one handle arrives at a map carrying one,
// and whichever the decoder kept is the one that gets verified -
// chosen by the wallet's key order rather than by anything this
// verifier decided.

// presentationDepth is where a presentation object sits inside a
// vp_token: the envelope is an object of query ids (depth 0), each
// value is an array (depth 1), and its elements are presentations
// (depth 2).
//
// Depth, and not the key's spelling, because a credential query id may
// legitimately BE "results". Skipping by name alone let a presentation
// under that query id escape the scan entirely, so two `proof` members
// in it were accepted and the decoder kept the last.
const presentationDepth = 2

// refuseDuplicateJSONMembers refuses a repeated member anywhere except
// the immediate keys of a presentation's "results".
//
// Those are handles, and a repeated handle is its own refusal with its
// own code, reported later - the shared specification orders handle
// checks after the presentation's own members so that a response wrong
// in two places is reported identically by every implementation.
//
// Note that this still descends INTO each result value: a repeat
// inside `{"satisfied": true, "satisfied": true}` is a repeated
// member, not a repeated handle.
func refuseDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanForDuplicates(decoder, 0, true); err != nil {
		if refusal, ok := err.(*CircuitZkResponseError); ok {
			return refusal
		}
		// A scan that cannot run is not a duplicate; it is an
		// unparseable response, which the caller's own decode reports
		// with the right code.
		return nil
	}
	return nil
}

// refuseDuplicateHandles refuses a repeated key among the IMMEDIATE
// keys of one results object.
//
// Immediate only. Recursing would report a repeat inside a result
// value - `{"satisfied": true, "satisfied": true}` - as a duplicate
// handle, which it is not, and would do so before the handle checks
// that must come first.
func refuseDuplicateHandles(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil
	}

	seen := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil
		}
		if seen[key] {
			return refuse(ReasonDuplicateHandle, "handle %q appears more than once", key)
		}
		seen[key] = true
		if err := skipValue(decoder); err != nil {
			return nil
		}
	}
	return nil
}

// refuseDuplicateResultMembers refuses a repeated member inside one
// result object.
//
// Checked where result values are, which is after the handle checks -
// so a response with both an unexpected handle and a repeated result
// member is refused for the handle, as the shared order requires.
func refuseDuplicateResultMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanForDuplicates(decoder, presentationDepth+1, false); err != nil {
		if refusal, ok := err.(*CircuitZkResponseError); ok {
			return refusal
		}
		return nil
	}
	return nil
}

// scanForDuplicates walks one JSON value, reporting the first repeated
// member name it finds.
//
// depth is how deep this value sits in a vp_token, so that the
// "results" member can be recognised by position rather than by
// spelling. skipResultKeys is false for a scan that was handed a
// subtree directly.
func scanForDuplicates(decoder *json.Decoder, depth int, skipResultKeys bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}

	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return io.ErrUnexpectedEOF
			}
			if seen[key] {
				return refuse(ReasonDuplicateMember, "member %q appears more than once", key)
			}
			seen[key] = true

			if skipResultKeys && depth == presentationDepth && key == "results" {
				// Skipped WHOLE, keys and values alike.
				//
				// The keys are handles, whose repeats have their own
				// code. The values' repeats are ordinary duplicate
				// members - but they are reported during result-value
				// validation, which runs AFTER the handle checks. A
				// response carrying both an unexpected handle and a
				// repeated member inside some result's value must be
				// refused for the handle, and finding the member here
				// would report it first.
				if err := skipValue(decoder); err != nil {
					return err
				}
				continue
			}
			if err := scanForDuplicates(decoder, depth+1, skipResultKeys); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanForDuplicates(decoder, depth+1, skipResultKeys); err != nil {
				return err
			}
		}
	}
	// The matching closing delimiter.
	_, err = decoder.Token()
	return err
}

// skipValue consumes one value without inspecting it.
func skipValue(decoder *json.Decoder) error {
	var value json.RawMessage
	return decoder.Decode(&value)
}
