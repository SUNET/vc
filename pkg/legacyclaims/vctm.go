package legacyclaims

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// IsVCTM reports whether src is a type metadata document: a JSON object
// with a member vct or claims, and without the member doctype of a mdoc
// schema.
func IsVCTM(src []byte) bool {
	if !json.Valid(src) {
		return false
	}
	root, err := readJSON(json.NewDecoder(bytes.NewReader(src)))
	if err != nil || root.kind != jsonObject {
		return false
	}
	return (root.member("vct") != nil || root.member("claims") != nil) && root.member("doctype") == nil
}

// VCTMSpellings returns a record per claim path key of a type metadata
// document that some readers read as the earlier release did and the
// others read as written: a key name[i], the key "*" and the key "null".
// raw is the document, and file names it. The note of each record says
// which readers read the key which way; migrate_claim_paths leaves each
// such key as written.
func VCTMSpellings(file string, raw []byte) ([]Rewrite, error) {
	root, err := readJSON(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	// encoding/json fills a struct field from the last member whose key
	// equals the field's name under case folding.
	claims := root.member("claims")
	if claims == nil {
		return nil, nil
	}
	var rewrites []Rewrite
	for i, claim := range claims.array {
		path := claim.member("path")
		if path == nil {
			continue
		}
		for j, element := range path.array {
			if element.kind != jsonString {
				continue
			}
			spelling, ok := vctmSpelling(element.text)
			if !ok {
				continue
			}
			rewrites = append(rewrites, Rewrite{
				File: file,
				Path: fmt.Sprintf("$.claims[%d].path[%d]", i, j),
				Line: bytes.Count(raw[:element.end], []byte("\n")) + 1,
				Old:  strconv.Quote(element.text),
				New:  spelling.standard,
				Note: spelling.note,
			})
		}
	}
	return rewrites, nil
}

// legacySpelling is a type metadata claim path key that the readers read
// in two ways.
type legacySpelling struct {
	// standard is the claims path pointer text of the earlier reading.
	standard string
	// note says which readers read the key which way, and what to write.
	note string
}

// vctmSpelling returns the reading of a type metadata claim path key that
// the readers read in two ways, and reports whether they do.
func vctmSpelling(key string) (legacySpelling, bool) {
	if name, index, ok := sdjwtvc.BracketIndex(key); ok {
		standard := fmt.Sprintf("%s, %d", strconv.Quote(name), index)
		return legacySpelling{
			standard: standard,
			note:     fmt.Sprintf("the consent page and the SVG template read a key written name[i] as element i of the array name, and the other readers read the key as written; write %s to select the element for every reader", standard),
		}, true
	}
	switch key {
	case "*":
		return legacySpelling{
			standard: "null",
			note:     `the issuer's filter of a credential built from a presentation reads the key "*" as null, and the other readers read the key as written; write null to select every element for every reader`,
		}, true
	case "null":
		return legacySpelling{
			standard: "null",
			note:     `a verifier preset that lists no claims of the credential requests the key "null" as null, and the other readers read the key as written; write null to select every element for every reader`,
		}, true
	}
	return legacySpelling{}, false
}

// jsonKind is the kind of a JSON value.
type jsonKind uint8

const (
	jsonOther jsonKind = iota
	jsonString
	jsonObject
	jsonArray
)

// jsonValue is a JSON value, with the offset just past its text.
type jsonValue struct {
	kind jsonKind
	// text is the value of a string.
	text string
	// members are the members of an object, in order.
	members []jsonMember
	// array holds the elements of an array.
	array []*jsonValue
	end   int64
}

// jsonMember is one member of a JSON object.
type jsonMember struct {
	key   string
	value *jsonValue
}

// member returns the value of the last member of an object whose key
// equals name under case folding, and nil for any other value.
func (v *jsonValue) member(name string) *jsonValue {
	if v.kind != jsonObject {
		return nil
	}
	var found *jsonValue
	for _, m := range v.members {
		if bytes.EqualFold([]byte(m.key), []byte(name)) {
			found = m.value
		}
	}
	return found
}

// readJSON reads the next JSON value of a decoder.
func readJSON(decoder *json.Decoder) (*jsonValue, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		return readJSONCollection(decoder, t)
	case string:
		return &jsonValue{kind: jsonString, text: t, end: decoder.InputOffset()}, nil
	}
	return &jsonValue{kind: jsonOther, end: decoder.InputOffset()}, nil
}

// readJSONCollection reads the members or elements of the object or array
// that opens with delim.
func readJSONCollection(decoder *json.Decoder, delim json.Delim) (*jsonValue, error) {
	value := &jsonValue{kind: jsonArray}
	if delim == '{' {
		value.kind = jsonObject
	}
	for decoder.More() {
		var key string
		if value.kind == jsonObject {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			text, ok := token.(string)
			if !ok {
				return nil, errors.New("a JSON object member has no string key")
			}
			key = text
		}
		element, err := readJSON(decoder)
		if err != nil {
			return nil, err
		}
		if value.kind == jsonObject {
			value.members = append(value.members, jsonMember{key: key, value: element})
		} else {
			value.array = append(value.array, element)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	value.end = decoder.InputOffset()
	return value, nil
}
