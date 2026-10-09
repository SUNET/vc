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

// Validate is the opaque entry point for revocation checking, for claims
// from a format that RESERVES the `status` member for the Token Status List
// reference - SD-JWT VC, JWP, W3C VC 2.0.
//
// mdoc does not: its claims are data elements that may be named anything,
// including `status`. Those callers want ValidateShaped with
// StatusClaimMayBeData, or an mdoc data element called `status` makes every
// such credential unverifiable. The distinction cannot be recovered here -
// the claims map has lost the format by the time it arrives - so it is a
// parameter, and this signature is the one that was already here, kept so
// existing callers still compile and still get the stricter reading.
func (r *Registry) Validate(ctx context.Context, claims map[string]any) (*CheckResult, error) {
	return r.ValidateShaped(ctx, claims, StatusClaimIsReserved)
}

// ValidateShaped is Validate with the format's `status` convention stated.
// It tries each registered checker's Extract() against the claims;
// the first one that returns a non-nil Reference is used for the status check.
//
// Returns (nil, nil) if the credential has no revocation information.
//
// shape says whether a scalar `status` could legitimately be credential
// data in the format these claims came from. The claims map has lost that
// by the time it arrives here, and the answer differs: SD-JWT VC and JWP
// reserve `status` for the Token Status List reference, mdoc claims include
// data elements that may be named anything. See StatusClaimShape.
func (r *Registry) ValidateShaped(ctx context.Context, claims map[string]any, shape StatusClaimShape) (*CheckResult, error) {
	for _, checker := range r.checkers {
		if ref := checker.Extract(claims); ref != nil {
			return checker.CheckStatus(ctx, ref)
		}
	}

	// Nothing extracted. If the credential itself says it carries revocation
	// information, that is not "not revocable" - it is a credential whose
	// revocation state we cannot determine, because the mechanism it names
	// is one no registered checker implements or the entry is malformed.
	// Returning (nil, nil) here would let a revoked credential through on
	// an unrecognised type name.
	//
	// The caller's fail_open setting governs what happens next, exactly as
	// it does for a status list that could not be fetched: this is the same
	// class of answer, "unknown", and must not be silently downgraded to
	// "fine".
	if declaresStatus(claims, shape) {
		return nil, fmt.Errorf("credential declares revocation information that no registered checker could read")
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
