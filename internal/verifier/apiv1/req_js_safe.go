package apiv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// reqSurvivesTheBrowser reports whether every number in items can make the
// round trip through the picker unchanged, and names the first that
// cannot.
//
// The picker receives this metadata as JSON, parses it, and posts a query
// back - so every value crosses JavaScript, where a number is a float64
// and nothing else. 9007199254740993 comes back as 9007199254740992.
//
// For most of this metadata that would be a curiosity. For req it is not:
// params are INPUTS TO A PROOF. A wallet computing a pseudonym over a
// changed parameter produces a different pseudonym, and the only symptom
// is two systems that disagree about who someone is - with nothing
// malformed anywhere to point at.
//
// Go's own serialisers preserve these exactly (decodeExact uses
// json.Decoder.UseNumber precisely so configuration survives verbatim),
// which is what makes this worth checking rather than assuming: the
// server half is lossless and the loss happens entirely in the browser.
//
// Checked by walking the ENCODED form rather than the map, so it does not
// matter whether a value arrived as an int from YAML, a json.Number from
// JSON, or a float64 from either.
func reqSurvivesTheBrowser(items []openid4vp.ReqItem) error {
	for i, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("req[%d]: %w", i, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var walk func(any) error
		walk = func(value any) error {
			switch typed := value.(type) {
			case json.Number:
				if !survivesFloat64(typed.String()) {
					return fmt.Errorf("req[%d]: %s cannot be represented exactly as a JavaScript number, and the picker posts this query back through one", i, typed.String())
				}
			case map[string]any:
				for _, v := range typed {
					if err := walk(v); err != nil {
						return err
					}
				}
			case []any:
				for _, v := range typed {
					if err := walk(v); err != nil {
						return err
					}
				}
			}
			return nil
		}
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			return fmt.Errorf("req[%d]: %w", i, err)
		}
		if err := walk(decoded); err != nil {
			return err
		}
	}
	return nil
}

// survivesFloat64 reports whether a JSON number literal is exactly
// representable as a float64 - which is what a JavaScript number is.
//
// Compared as exact rationals rather than by magnitude: "beyond 2^53" is
// the familiar case but not the only one, and a decimal fraction can lose
// precision well inside it.
func survivesFloat64(literal string) bool {
	exact, ok := new(big.Rat).SetString(literal)
	if !ok {
		return false
	}
	asFloat, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		return false
	}
	rounded := new(big.Rat).SetFloat64(asFloat)
	return rounded != nil && rounded.Cmp(exact) == 0
}
