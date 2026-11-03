package openid4vp

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

type VPResponse struct {
	VPToken map[string][]string `json:"vp_token,omitempty" bson:"vp_token" validate:"required"`
	State   string              `json:"state,omitempty" bson:"state" validate:"required"`

	// VPTokenRaw is every vp_token entry as it arrived, before any
	// decoding.
	//
	// Needed because not every presentation is a string. A circuit_zk
	// presentation is an OBJECT, and its validation has to run on the
	// raw text: a repeated member or a repeated result handle cannot
	// be seen after decoding, since Go keeps the last of a repeated
	// key and discards the other silently.
	//
	// Not persisted (bson:"-") and not serialised: it is the input
	// bytes, kept for the length of one verification. A round trip
	// through storage would re-encode them, and re-encoded bytes are
	// exactly the ones a duplicate check can no longer see.
	VPTokenRaw map[string]json.RawMessage `json:"-" bson:"-"`

	// VPTokenEnvelope is the whole vp_token object as it arrived.
	//
	// The ENVELOPE and not only its entries, because a validator that
	// checks the envelope - a repeated query id, the shape of the
	// object itself - has to see the object. Handing it one entry
	// would silently drop those checks and, worse, hand it an array
	// where it expects a map.
	//
	// Same lifetime and same reason as VPTokenRaw: input bytes, kept
	// for one verification, never persisted. A round trip through
	// storage would re-encode them, and re-encoded bytes are the ones
	// a duplicate check can no longer see.
	VPTokenEnvelope json.RawMessage `json:"-" bson:"-"`
}

// UnmarshalJSON implements custom JSON unmarshaling for VPResponse.
// Handles the different vp_token formats wallets may send:
//   - DCQL object: {"credential_id": "token"} or {"credential_id": ["token1", "token2"]}
//   - Single string: "token" (mapped to first scope or "_default" key)
//
// A vp_token that carries no token is refused however it is spelled - null, an
// empty object, a key with null or [] under it, or an empty token string. The
// scope loop downstream also refuses a scope it finds no token for, so this is
// the fail-closed half rather than the only check; what it fixes is a parser
// that accepted a response contradicting its own "missing or empty" rule.
func (v *VPResponse) UnmarshalJSON(data []byte) error {
	// Use a raw intermediary to handle flexible vp_token types
	var raw struct {
		VPToken json.RawMessage `json:"vp_token"`
		State   string          `json:"state"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.State == "" {
		return fmt.Errorf("state: missing or empty")
	}
	v.State = raw.State

	if len(raw.VPToken) == 0 {
		return fmt.Errorf("vp_token: missing or empty")
	}

	v.VPToken = make(map[string][]string)
	v.VPTokenRaw = make(map[string]json.RawMessage)
	v.VPTokenEnvelope = raw.VPToken

	// Try as object (DCQL format): {"id": "token"} or {"id": ["token1","token2"]}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw.VPToken, &obj); err == nil {
		for key, val := range obj {
			v.VPTokenRaw[key] = val
			// Try as string first
			var s string
			if err := json.Unmarshal(val, &s); err == nil {
				if s == "" {
					return fmt.Errorf("vp_token[%q]: empty token", key)
				}
				v.VPToken[key] = []string{s}
				continue
			}
			// Try as array of strings
			var arr []string
			if err := json.Unmarshal(val, &arr); err == nil {
				// A key present with nothing under it is not a presentation.
				// null and [] both arrive here, and both named a credential
				// the wallet then did not supply.
				if len(arr) == 0 {
					return fmt.Errorf("vp_token[%q]: no token", key)
				}
				for i, token := range arr {
					if token == "" {
						return fmt.Errorf("vp_token[%q][%d]: empty token", key, i)
					}
				}
				v.VPToken[key] = arr
				continue
			}
			// An array of OBJECTS is a presentation format whose
			// elements are not strings - circuit_zk is the first.
			// It stays in VPTokenRaw only: the string map is what
			// every other format reads, and putting a re-encoded
			// object in it would hand that format a token it cannot
			// parse while hiding the raw bytes the new one needs.
			//
			// Anything else still fails here. Admitting one more
			// legitimate shape is not the same as admitting
			// everything.
			if isArrayOfObjects(val) {
				continue
			}
			return fmt.Errorf("vp_token[%q]: expected string or array of strings", key)
		}
		// JSON null unmarshals into a map WITHOUT error, leaving a nil map -
		// so "vp_token": null reached here having passed the emptiness check
		// above, which tests the raw bytes and sees four of them. An empty
		// object arrives the same way. Either is a response that presented
		// nothing while claiming the shape of one.
		//
		// Counted over the RAW entries, not the string map: a
		// response carrying only object presentations - a circuit_zk
		// one, where every entry is an array of objects - leaves the
		// string map empty and is a perfectly good response. Counting
		// the string map here refused it before anything could
		// dispatch it.
		if len(v.VPTokenRaw) == 0 {
			return fmt.Errorf("vp_token: missing or empty")
		}
		return nil
	}

	// Try as plain string (single VP token)
	var s string
	if err := json.Unmarshal(raw.VPToken, &s); err == nil {
		if s == "" {
			return fmt.Errorf("vp_token: missing or empty")
		}
		v.VPToken["_default"] = []string{s}
		return nil
	}

	return fmt.Errorf("vp_token: expected JSON object (map of credential ID to token) or a plain string, got unsupported type")
}

type ResponseParameters struct {
	// VPToken REQUIRED. The structure of this parameter depends on the query language used to request the presentations in the Authorization Request:
	VPToken string `json:"vp_token,omitempty" bson:"vp_token" validate:"omitempty,required_if=ResponseType vp_token"`

	Code    string `json:"code,omitempty" bson:"code"`
	ISS     string `json:"iss,omitempty" bson:"iss"`
	State   string `json:"state,omitempty" bson:"state"`
	IDToken string `json:"id_token,omitempty" bson:"id_token"`

	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty" bson:"presentation_submission"`
}

// BuildCredential unwraps the VPToken from the ResponseParameters
func (r *ResponseParameters) BuildCredential() (map[string]any, error) {
	if isMDocFormatToken(r.VPToken) {
		return extractMDocClaimsFromToken(r.VPToken)
	}

	parsed, err := sdjwtvc.Token(r.VPToken).Parse()
	if err != nil {
		return nil, err
	}

	return parsed.Claims, nil
}

// Validate validates the response parameters according to OpenID4VP spec Section 8.1
func (r *ResponseParameters) Validate() error {
	if r.VPToken == "" {
		return fmt.Errorf("vp_token is required")
	}

	// Validate VP Token format
	if _, err := r.BuildCredential(); err != nil {
		return fmt.Errorf("invalid vp_token format: %w", err)
	}

	return nil
}

// ToJSON serializes the response parameters to JSON
func (r *ResponseParameters) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ResponseParametersFromJSON deserializes the response parameters from JSON
func ResponseParametersFromJSON(data []byte) (*ResponseParameters, error) {
	var r ResponseParameters
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// isArrayOfObjects reports whether raw is a non-empty JSON array whose
// every element is an object.
//
// Deliberately narrow. It admits exactly the shape a circuit_zk
// presentation array has, so a vp_token entry that is a number, a
// nested array or a mix keeps failing with the message it always had.
func isArrayOfObjects(raw json.RawMessage) bool {
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil || len(elements) == 0 {
		return false
	}
	for _, element := range elements {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(element, &object); err != nil {
			return false
		}
	}
	return true
}
