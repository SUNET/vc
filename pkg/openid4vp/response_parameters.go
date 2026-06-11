package openid4vp

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

type VPResponse struct {
	VPToken map[string][]string `json:"vp_token,omitempty" bson:"vp_token" validate:"required"`
	State   string              `json:"state,omitempty" bson:"state" validate:"required"`
}

// UnmarshalJSON implements custom JSON unmarshaling for VPResponse.
// Handles the different vp_token formats wallets may send:
//   - DCQL object: {"credential_id": "token"} or {"credential_id": ["token1", "token2"]}
//   - Single string: "token" (mapped to first scope or "_default" key)
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

	// Try as object (DCQL format): {"id": "token"} or {"id": ["token1","token2"]}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw.VPToken, &obj); err == nil {
		for key, val := range obj {
			// Try as string first
			var s string
			if err := json.Unmarshal(val, &s); err == nil {
				v.VPToken[key] = []string{s}
				continue
			}
			// Try as array of strings
			var arr []string
			if err := json.Unmarshal(val, &arr); err == nil {
				v.VPToken[key] = arr
				continue
			}
			return fmt.Errorf("vp_token[%q]: expected string or array of strings", key)
		}
		return nil
	}

	// Try as plain string (single VP token)
	var s string
	if err := json.Unmarshal(raw.VPToken, &s); err == nil {
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
