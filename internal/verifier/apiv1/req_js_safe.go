package apiv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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
				if !survivesTheBrowser(typed.String()) {
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

// survivesTheBrowser reports whether a JSON number literal denotes the
// same number after a JavaScript JSON.parse/JSON.stringify round trip.
//
// Not the same question as "is it exactly representable as a float64",
// which is what this asked at first. 0.1 is NOT exactly representable and
// survives perfectly: ECMAScript prints the shortest decimal that parses
// back to the same double, so 0.1 comes out "0.1". Testing
// representability refused presets that were fine.
//
// And the two differ in the other direction as well, which is the part I
// would not have predicted: 4611686018427387904 (2^62) IS exactly
// representable and does not survive - the shortest round-tripping
// decimal for it is 4611686018427388000, so that is what the picker posts
// back. A wallet reading it as an integer gets a different number than
// the one configured.
//
// So the test is on the VALUE the wallet ends up with: take the literal
// to a float64 as the browser does, print the shortest decimal that
// round-trips as the browser does, and compare that against the original
// as exact rationals. Comparing values rather than text on purpose - JS
// prints 1.0 as "1", which is a different spelling of the same number and
// changes no proof.
func survivesTheBrowser(literal string) bool {
	exact, ok := new(big.Rat).SetString(literal)
	if !ok {
		return false
	}
	asFloat, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		// Out of float64 range. JSON.stringify turns an Infinity into
		// null, so the parameter does not merely change - it disappears.
		return false
	}
	if math.IsInf(asFloat, 0) || math.IsNaN(asFloat) {
		return false
	}
	printed, ok := new(big.Rat).SetString(strconv.FormatFloat(asFloat, 'g', -1, 64))
	return ok && printed.Cmp(exact) == 0
}
