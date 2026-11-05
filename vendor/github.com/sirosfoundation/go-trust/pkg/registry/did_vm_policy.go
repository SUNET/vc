package registry

import (
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// DenyMissingVerificationMethods enforces the did.required_verification_methods
// policy constraint, which the manager injects into the request context under
// "required_verification_methods". It is shared by every DID-resolving
// registry (did:web, did:webvh, did:jwks and the generic DID resolver).
//
// The DID document must contain ALL of the required types among the `type`
// values of its top-level verificationMethod array (exact, case-sensitive,
// like required_services). Methods embedded in relationship arrays such as
// authentication or assertionMethod are not considered. It returns nil when
// the constraint is unset or satisfied, otherwise a deny response.
func DenyMissingVerificationMethods[T any](ctx map[string]interface{}, methods []T, typeOf func(T) string, startTime time.Time) *authzen.EvaluationResponse {
	required := contextStrings(ctx["required_verification_methods"])
	if len(required) == 0 {
		return nil
	}
	present := make(map[string]bool, len(methods))
	for _, m := range methods {
		present[typeOf(m)] = true
	}
	for _, r := range required {
		if !present[r] {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":                         "DID document missing required verification methods for this role",
						"required_verification_methods": required,
						"resolution_ms":                 time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}
	return nil
}

// contextStrings converts a context value ([]string or []interface{}) to []string.
func contextStrings(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
