package registry

import (
	"context"
	"fmt"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// MockRegistry is a test helper that implements TrustRegistry
type MockRegistry struct {
	name                   string
	decision               bool
	types                  []string
	err                    error
	refreshErr             error
	supportsResolutionOnly bool
	trustMetadata          interface{}
}

// Name returns the mock registry name
func (m *MockRegistry) Name() string {
	return m.name
}

// Info returns mock registry information
func (m *MockRegistry) Info() RegistryInfo {
	return RegistryInfo{
		Name:        m.name,
		Type:        "mock",
		Description: "Mock registry for testing",
		Version:     "1.0.0",
	}
}

// SupportedResourceTypes returns the resource types this mock supports
func (m *MockRegistry) SupportedResourceTypes() []string {
	return m.types
}

// SupportsResolutionOnly returns whether this mock supports resolution-only requests
func (m *MockRegistry) SupportsResolutionOnly() bool {
	return m.supportsResolutionOnly
}

// Evaluate returns the configured decision or error
func (m *MockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if m.err != nil {
		return nil, m.err
	}

	response := &authzen.EvaluationResponse{
		Decision: m.decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": m.name,
			},
		},
	}

	// Include trust metadata if configured
	if m.trustMetadata != nil {
		response.Context.TrustMetadata = m.trustMetadata
	}

	return response, nil
}

// Healthy always returns true for mock registries
func (m *MockRegistry) Healthy() bool {
	return m.err == nil
}

// Refresh returns the configured refreshErr for mock registries
func (m *MockRegistry) Refresh(ctx context.Context) error {
	return m.refreshErr
}

// mockRegistryName returns a consistent name for test registries
func mockRegistryName(i int) string {
	names := []string{"registry-0", "registry-1", "registry-2", "registry-3", "registry-4", "registry-5"}
	if i < len(names) {
		return names[i]
	}
	return "registry-unknown"
}

// createTestRequest creates a standard test request
func createTestRequest() *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test-subject",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test-subject",
			Key:  []interface{}{"dummy-cert"},
		},
	}
}

// CheckRequiredVerificationMethodsEnforcement is a shared conformance check for
// DID registries. newMethod builds a verification method of the registry's own
// type with the given `type` string; check must evaluate the registry's policy
// constraints for a DID document holding exactly those methods, with ctx as the
// request context, and return the denial (nil when allowed). It returns an
// error describing the first case the registry gets wrong.
func CheckRequiredVerificationMethodsEnforcement[M any](newMethod func(typ string) M, check func(ctx map[string]interface{}, methods []M) *authzen.EvaluationResponse) error {
	methods := []M{newMethod("JsonWebKey2020"), newMethod("Multikey")}
	cases := []struct {
		name     string
		required []string
		deny     bool
	}{
		{"all present", []string{"JsonWebKey2020", "Multikey"}, false},
		{"missing type", []string{"Ed25519VerificationKey2020"}, true},
		{"partially present", []string{"JsonWebKey2020", "Ed25519VerificationKey2020"}, true},
		{"unset", nil, false},
	}
	for _, c := range cases {
		ctx := map[string]interface{}{}
		if c.required != nil {
			ctx["required_verification_methods"] = c.required
		}
		resp := check(ctx, methods)
		if denied := resp != nil && !resp.Decision; denied != c.deny {
			return fmt.Errorf("%s: deny=%v, want %v", c.name, denied, c.deny)
		}
	}
	return nil
}
