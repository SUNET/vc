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
// carrying two values for one handle arrives at a map as a response
// carrying one, and whichever the decoder kept is the one that gets
// verified - chosen by the wallet's key order rather than by anything
// this verifier decided.

// refuseDuplicateJSONMembers refuses a repeated member anywhere
// OUTSIDE a "results" object.
//
// Results are skipped here because a repeated handle is its own
// refusal, reported later, when handles are checked - the shared
// specification orders it that way so a response that is wrong in two
// places is reported the same way by every implementation.
func refuseDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanForDuplicates(decoder, true); err != nil {
		var refusal *CircuitZkResponseError
		if ok := asRefusal(err, &refusal); ok {
			return refusal
		}
		// A scan that cannot run is not a duplicate; it is an
		// unparseable response, and the caller's decode reports that
		// with the right code.
		return nil
	}
	return nil
}

// refuseDuplicateHandles refuses a repeated key in one results object.
func refuseDuplicateHandles(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanForDuplicates(decoder, false); err != nil {
		var refusal *CircuitZkResponseError
		if ok := asRefusal(err, &refusal); ok {
			// Inside a results object, a repeat IS a repeated handle.
			return refuse(ReasonDuplicateHandle, "%s", refusal.Detail)
		}
		return nil
	}
	return nil
}

// scanForDuplicates walks one JSON value, reporting the first repeated
// member name it finds.
//
// skipResults is what separates the two passes: the envelope pass does
// not look inside a "results" object, and the handles pass is given
// one directly.
func scanForDuplicates(decoder *json.Decoder, skipResults bool) error {
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

			if skipResults && key == "results" {
				// Skipped whole: a repeat in here is a repeated
				// HANDLE, which is checked where handles are.
				if err := skipValue(decoder); err != nil {
					return err
				}
				continue
			}
			if err := scanForDuplicates(decoder, skipResults); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanForDuplicates(decoder, skipResults); err != nil {
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

// asRefusal reports whether err is one of this package's refusals.
func asRefusal(err error, target **CircuitZkResponseError) bool {
	refusal, ok := err.(*CircuitZkResponseError)
	if ok {
		*target = refusal
	}
	return ok
}
