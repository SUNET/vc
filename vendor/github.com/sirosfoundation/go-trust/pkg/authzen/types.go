// Package authzen provides types and functions for the AuthZEN protocol.
// AuthZEN is an authorization protocol that allows for policy decisions
// based on subject, resource, action, and context information.
//
// This implementation follows the AuthZEN Trust Registry Profile as specified in
// draft-johansson-authzen-trust: https://leifj.github.io/draft-johansson-authzen-trust/
package authzen

import "fmt"

// Subject represents the name part of the name-to-key binding in a trust evaluation request.
// According to the AuthZEN Trust Registry Profile:
// - type MUST be the constant string "key"
// - id MUST be the name bound to the public key to be validated
// @Description Subject in an AuthZEN trust evaluation request
type Subject struct {
	Type string `json:"type" example:"key"`           // MUST be "key"
	ID   string `json:"id" example:"did:example:123"` // The name bound to the public key
}

// Resource represents the public key part of the name-to-key binding in a trust evaluation request.
// According to the AuthZEN Trust Registry Profile:
// - type MUST be one of "jwk" or "x5c"
// - id MUST be the same as subject.id
// - key MUST contain the public key in the format specified by type
// @Description Resource (public key) in an AuthZEN trust evaluation request
type Resource struct {
	Type string        `json:"type" example:"x5c"`             // MUST be "jwk" or "x5c"
	ID   string        `json:"id" example:"did:example:123"`   // MUST match subject.id
	Key  []interface{} `json:"key" swaggertype:"array,string"` // Public key data (JWK object or x5c array)
}

// Action represents the role associated with the name-to-key binding.
// This is optional and used to distinguish different uses of the same name-to-key binding.
// For example, to authorize that an X.509 certificate is allowed to act as a TLS server
// or as a digital credential issuer.
//
// The Parameters field allows additional role-specific constraints. The interpretation
// of parameters is defined by the action.name value. Common parameters include:
//   - credential_types: array of credential type identifiers (e.g., SD-JWT VCT values)
//   - query: credential query object (e.g., DCQL)
//
// @Description Action (role) in an AuthZEN trust evaluation request
type Action struct {
	Name       string                 `json:"name" example:"http://ec.europa.eu/NS/wallet-provider"` // The role name
	Parameters map[string]interface{} `json:"parameters,omitempty" swaggertype:"object"`             // Role-specific constraints
}

// EvaluationRequest represents a trust evaluation request according to the AuthZEN Trust Registry Profile.
// The client (PEP) requests that the server (PDP) authorizes the binding between the name
// specified by Subject and the public key specified by Resource. Optionally, Action constrains
// the authorization to a specific role.
// @Description AuthZEN trust evaluation request (draft-johansson-authzen-trust)
type EvaluationRequest struct {
	Subject  Subject                `json:"subject"`                                       // The name to be bound to the key
	Resource Resource               `json:"resource"`                                      // The public key to be validated
	Action   *Action                `json:"action,omitempty"`                              // Optional role constraint
	Context  map[string]interface{} `json:"context,omitempty" swaggertype:"object,string"` // Optional context (MUST NOT be critical)
}

// EvaluationResponse represents the authorization decision response in the AuthZEN protocol.
// This profile does not constrain or profile the standard AuthZEN response message format.
// @Description AuthZEN evaluation response with trust decision
type EvaluationResponse struct {
	Decision bool                       `json:"decision" example:"true"` // Whether the name-to-key binding is authorized
	Context  *EvaluationResponseContext `json:"context,omitempty"`       // Optional context with decision details
}

// EvaluationResponseContext contains additional information about an authorization decision.
// According to the AuthZEN Trust Registry Profile, this context may include trust_metadata
// for resolution-only requests or as additional information for trust evaluation responses.
// @Description Context information for evaluation response
type EvaluationResponseContext struct {
	ID     string                 `json:"id,omitempty" example:"decision-123"`   // Optional identifier for the decision
	Reason map[string]interface{} `json:"reason,omitempty" swaggertype:"object"` // Reason information (user or admin)
	// TrustMetadata contains the resolved trust metadata for the subject.
	// For DID resolution: contains the DID Document
	// For OpenID Federation: contains the Entity Configuration
	// This field is set when trust_metadata is requested or for resolution-only requests.
	TrustMetadata interface{} `json:"trust_metadata,omitempty" swaggertype:"object"` // DID Document or Entity Configuration
}

// Validate checks if the EvaluationRequest is compliant with the AuthZEN Trust Registry Profile.
// Returns an error if the request doesn't meet the specification requirements.
//
// Per the specification, requests can be either:
// 1. Full trust evaluation: validates name-to-key binding (requires resource.type and resource.key)
// 2. Resolution-only: retrieves trust metadata without key validation (resource.type and resource.key optional)
//
// Resolution-only requests are supported by registries that implement SupportsResolutionOnly().
func (r *EvaluationRequest) Validate() error {
	// Subject.type MUST be "key" or "url"
	if r.Subject.Type != "key" && r.Subject.Type != "url" {
		return fmt.Errorf("subject.type must be 'key' or 'url', got '%s'", r.Subject.Type)
	}

	// Subject.id MUST be present
	if r.Subject.ID == "" {
		return fmt.Errorf("subject.id must be present")
	}

	// Check if this is a resolution-only request (no type or key)
	if r.IsResolutionOnlyRequest() {
		// For resolution-only requests, we only need subject.id
		// Resource.id should match subject.id if present
		if r.Resource.ID != "" && r.Resource.ID != r.Subject.ID {
			return fmt.Errorf("resource.id (%s) must match subject.id (%s)", r.Resource.ID, r.Subject.ID)
		}
		return nil
	}

	// For full trust evaluation requests:

	// Resource.type MUST be "jwk" or "x5c"
	if r.Resource.Type != "jwk" && r.Resource.Type != "x5c" {
		return fmt.Errorf("resource.type must be 'jwk' or 'x5c', got '%s'", r.Resource.Type)
	}

	// Resource.id MUST be present and MUST match subject.id
	if r.Resource.ID == "" {
		return fmt.Errorf("resource.id must be present")
	}
	if r.Resource.ID != r.Subject.ID {
		return fmt.Errorf("resource.id (%s) must match subject.id (%s)", r.Resource.ID, r.Subject.ID)
	}

	// Resource.key MUST be present
	if len(r.Resource.Key) == 0 {
		return fmt.Errorf("resource.key must be present and non-empty")
	}

	return nil
}

// IsResolutionOnlyRequest returns true if the request is a resolution-only request.
// Resolution-only requests have no resource.type or no resource.key, meaning they
// are only requesting trust metadata (DID document, entity configuration, etc.)
// without validating a specific name-to-key binding.
func (r *EvaluationRequest) IsResolutionOnlyRequest() bool {
	return r.Resource.Type == "" || len(r.Resource.Key) == 0
}

// PDPMetadata represents Policy Decision Point metadata as defined in Section 9 of the
// AuthZEN base specification. This metadata is served at the .well-known discovery endpoint.
// @Description Policy Decision Point metadata for service discovery
type PDPMetadata struct {
	// REQUIRED. The Policy Decision Point identifier, which is a URL that uses the
	// "https" scheme and has no query or fragment components. This is used to prevent
	// PDP mix-up attacks.
	PolicyDecisionPoint string `json:"policy_decision_point" example:"https://pdp.example.com"`

	// REQUIRED. URL of Access Evaluation API endpoint
	AccessEvaluationEndpoint string `json:"access_evaluation_endpoint" example:"https://pdp.example.com/evaluation"`

	// OPTIONAL. URL of Access Evaluations API endpoint (for batch requests)
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty" example:"https://pdp.example.com/evaluations"`

	// OPTIONAL. URL of Search API endpoint for subject entities
	SearchSubjectEndpoint string `json:"search_subject_endpoint,omitempty" example:"https://pdp.example.com/search/subject"`

	// OPTIONAL. URL of Search API endpoint for resource entities
	SearchResourceEndpoint string `json:"search_resource_endpoint,omitempty" example:"https://pdp.example.com/search/resource"`

	// OPTIONAL. URL of Search API endpoint for action entities
	SearchActionEndpoint string `json:"search_action_endpoint,omitempty" example:"https://pdp.example.com/search/action"`

	// OPTIONAL. JSON array containing a list of registered IANA URNs referencing PDP
	// specific capabilities.
	Capabilities []string `json:"capabilities,omitempty" swaggertype:"array,string"`

	// OPTIONAL. A JWT containing metadata parameters about the protected resource as claims.
	// This provides signed metadata that takes precedence over plain JSON metadata.
	SignedMetadata string `json:"signed_metadata,omitempty"`
}
