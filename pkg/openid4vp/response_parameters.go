package openid4vp

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

type VPResponse struct {
	VPToken map[string]string `json:"vp_token,omitempty" bson:"vp_token" validate:"required"`
	State   string            `json:"state,omitempty" bson:"state" validate:"required"`
}

type ResponseParameters struct {
	//VPToken REQUIRED. The structure of this parameter depends on the query language used to request the presentations in the Authorization Request:
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
