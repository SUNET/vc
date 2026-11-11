package lote

// Embedded JWS: a JSON list whose top-level "signature" member is an object
// {"protected": "<b64url header>", "signature": "<b64url signature>"} and
// whose remaining members are the signed content. This is the shape published
// by the WE BUILD WP4 trust registry tooling (JAdES compact baseline B, with
// the compact serialisation split across the document).
//
// The signing input is ASCII(protected || "." || b64url(payload)) where
// payload is the document without its "signature" member, serialised as
// compact JSON with object members sorted by key and every non-ASCII
// character escaped as \uXXXX. A verifier cannot use the received bytes as
// they are (member order and whitespace are not covered), so it rebuilds that
// serialisation from the parsed document. The rebuilt bytes, not the received
// ones, are returned as the verified payload: they are what the signature
// covers.
//
// Only integer numbers are supported. A document with a fractional or
// exponent number cannot be reproduced byte for byte, so it is rejected
// rather than risk accepting content the signature does not cover.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// embeddedJWS is the parsed form of a document with an embedded signature.
type embeddedJWS struct {
	protected string
	signature string
	payload   []byte // canonical document without the signature member
}

// parseEmbeddedJWS returns (nil, nil) when raw is not a JSON object with a
// "signature" object member (so the caller can try other serialisations), and
// an error when it is one but is malformed.
func parseEmbeddedJWS(raw []byte) (*embeddedJWS, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, nil //nolint:nilerr // not a JSON object: not this serialisation
	}
	sigRaw, ok := members["signature"]
	if !ok {
		return nil, nil
	}
	var sig struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		return nil, nil //nolint:nilerr // "signature" is not an object of strings: not this serialisation
	}
	if sig.Protected == "" || sig.Signature == "" {
		return nil, errors.New("lote: embedded JWS signature needs both protected and signature")
	}
	if _, hasPayload := members["payload"]; hasPayload {
		return nil, errors.New("lote: embedded JWS document has a payload member")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("lote: decoding embedded JWS document: %w", err)
	}
	delete(doc, "signature")
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, doc); err != nil {
		return nil, err
	}
	return &embeddedJWS{protected: sig.Protected, signature: sig.Signature, payload: buf.Bytes()}, nil
}

// writeCanonicalJSON writes v (a value decoded with UseNumber) as compact
// JSON with sorted object keys and ASCII-only strings.
func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("lote: embedded JWS document has non-integer number %q, which cannot be canonicalised", s)
		}
		if s == "-0" {
			return errors.New("lote: embedded JWS document has number -0, which cannot be canonicalised")
		}
		buf.WriteString(s)
	case string:
		writeASCIIString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // UTF-8 byte order is code point order
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeASCIIString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("lote: unexpected JSON value of type %T", v)
	}
	return nil
}

// writeASCIIString writes s as a JSON string with every non-ASCII code point
// escaped as \uXXXX (lower-case hex, surrogate pairs above the BMP).
func writeASCIIString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	u := func(r rune) {
		buf.WriteString(`\u`)
		buf.WriteByte(hex[r>>12&0xf])
		buf.WriteByte(hex[r>>8&0xf])
		buf.WriteByte(hex[r>>4&0xf])
		buf.WriteByte(hex[r&0xf])
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20 || (r >= 0x7f && r < 0x10000):
			u(r)
		case r >= 0x10000:
			r -= 0x10000
			u(0xd800 + r>>10)
			u(0xdc00 + r&0x3ff)
		default:
			buf.WriteByte(byte(r))
		}
	}
	buf.WriteByte('"')
}
