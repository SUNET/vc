package revocation

import (
	"context"
	"fmt"
)

// Registry holds registered checkers, providing an opaque
// revocation validation method that callers use without knowing the mechanism.
type Registry struct {
	checkers []Checker
}

// NewRegistry creates a new Registry with the provided checkers.
// The registry is extensible: pass multiple Checker implementations to support
// different revocation mechanisms (Token Status List, OCSP, W3C Bitstring, etc.).
// Each checker declares which scheme it handles via Supports() and provides
// its own Extract() to find revocation references in credential claims.
func NewRegistry(checkers ...Checker) *Registry {
	return &Registry{checkers: checkers}
}

// Validate is the opaque entry point for revocation checking.
// It tries each registered checker's Extract() against the claims;
// the first one that returns a non-nil Reference is used for the status check.
//
// Returns (nil, nil) if the credential has no revocation information.
func (r *Registry) Validate(ctx context.Context, claims map[string]any) (*CheckResult, error) {
	for _, checker := range r.checkers {
		if ref := checker.Extract(claims); ref != nil {
			return checker.CheckStatus(ctx, ref)
		}
	}
	return nil, nil // Credential is not revocable
}

// CheckStatus dispatches to the appropriate checker based on the reference's scheme.
// Exposed for cases where the caller already has a Reference.
func (r *Registry) CheckStatus(ctx context.Context, ref *Reference) (*CheckResult, error) {
	if ref == nil {
		return nil, nil
	}
	for _, checker := range r.checkers {
		if checker.Supports(ref.Scheme) {
			return checker.CheckStatus(ctx, ref)
		}
	}
	return nil, fmt.Errorf("no checker registered for scheme: %s", ref.Scheme)
}
