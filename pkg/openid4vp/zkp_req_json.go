package openid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// A repeated JSON member name has to be judged on the RAW TEXT.
//
// A decoded object cannot represent one: every JSON decoder keeps one
// of the values and discards the other silently. So a vp_token
// carrying two entries for one query id arrives at a map as one entry,
// and whichever the decoder kept is the wallet's choice rather than
// anything this verifier decided.
//
// Unlike the pre-v0.4 shape there is nothing to skip: the results now
// live inside the CBOR presentation, where a repeated key is
// cbor_duplicate_key, so the whole JSON envelope is scanned.
func refuseDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanForDuplicates(decoder); err != nil {
		var refusal *ZkpReqResponseError
		if errors.As(err, &refusal) {
			return refusal
		}
		// A scan that cannot run is not a duplicate; it is an
		// unparseable response, and the caller's decode reports that
		// with the right code.
		return nil
	}
	return nil
}

func scanForDuplicates(decoder *json.Decoder) error {
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
			if err := scanForDuplicates(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanForDuplicates(decoder); err != nil {
				return err
			}
		}
	}
	// The matching closing delimiter.
	_, err = decoder.Token()
	return err
}

// decodeCanonicalBase64URL decodes unpadded base64url and refuses
// anything that is not the canonical spelling of those bytes.
//
// Decoding is not the same as the wire contract. Go's decoder skips CR
// and LF and accepts a final character whose unused low bits are set,
// so a value with a newline in it and a value differing only in those
// bits both decode - two spellings of one presentation, from a
// contract that says there is one. Re-encoding and comparing catches
// every non-canonical spelling at once, rather than a list of rules
// that has to stay complete.
func decodeCanonicalBase64URL(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("not unpadded base64url: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("not canonical unpadded base64url")
	}
	return raw, nil
}

// isJSONArray reports whether raw is a JSON array, by its first
// non-space byte. Shape, not contents.
//
// Before the decode, because Go's decoder accepts JSON null into a
// slice without error and leaves it nil - which would arrive as an
// empty array and be reported as the wrong refusal.
func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '['
}

// strictDecode decodes exactly one JSON value and refuses trailing
// content, and refuses JSON null as a value of the wrong type.
//
// Go's decoder treats null as "leave the target alone": into a string
// it is a no-op, into a slice or map it leaves nil, and NEITHER
// returns an error. Every member of a zkp_req response has a type and
// none of them may be null, so one place to be right about it.
func strictDecode(raw []byte, into any) error {
	if isJSONNull(raw) {
		return errors.New("the value is null")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the JSON value")
	}
	return nil
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
