// Package revocation provides a credential-format-agnostic interface for
// checking the revocation status of verifiable credentials.
//
// The interface is designed to support multiple revocation mechanisms:
//   - Token Status List (draft-ietf-oauth-status-list) — implemented
//   - OCSP, CRL, or future mechanisms — plug in via the Checker interface
package revocation

import (
	"context"
	"time"
)

// Scheme identifies the revocation mechanism type.
type Scheme string

const (
	// SchemeStatusList is the Token Status List mechanism (draft-ietf-oauth-status-list).
	SchemeStatusList Scheme = "status_list"
)

// Status represents the revocation status of a credential.
type Status int

const (
	// StatusValid indicates the credential is valid (not revoked).
	StatusValid Status = iota
	// StatusInvalid indicates the credential has been revoked.
	StatusInvalid
	// StatusSuspended indicates the credential is temporarily suspended.
	StatusSuspended
	// StatusUnknown indicates the status could not be determined.
	StatusUnknown
)

// String returns a string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusInvalid:
		return "invalid"
	case StatusSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// Reference contains the information needed to check a credential's revocation status.
// Each credential format (SD-JWT, mDoc, etc.) extracts this from its own claims structure.
type Reference struct {
	// Scheme identifies the revocation mechanism (e.g., "status_list").
	Scheme Scheme
	// URI is the endpoint to query for status information.
	URI string
	// Index is the credential's position within the status list (status_list scheme only).
	Index int64
}

// CheckResult contains the outcome of a revocation status check.
type CheckResult struct {
	// Status is the credential's revocation status.
	Status Status
	// StatusCode is the raw status byte from the underlying mechanism.
	StatusCode uint8
	// CheckedAt is when the check was performed.
	CheckedAt time.Time
	// URI is the status list URI that was checked.
	URI string
	// Index is the index that was checked.
	Index int64
}

// Checker is the interface for revocation status verification.
// Implementations handle specific revocation mechanisms (Token Status List, OCSP, etc.).
type Checker interface {
	// CheckStatus checks the revocation status of a credential.
	CheckStatus(ctx context.Context, ref *Reference) (*CheckResult, error)
	// Supports returns true if this checker handles the given scheme.
	Supports(scheme Scheme) bool
	// Extract extracts a revocation Reference from credential claims.
	// Returns nil if the claims don't contain revocation info for this mechanism.
	Extract(claims map[string]any) *Reference
}

// KeyResolver resolves public keys for verifying signed revocation tokens.
// Each checker implementation uses this to verify the authenticity of
// fetched revocation data (e.g., status list JWT signatures).
type KeyResolver interface {
	ResolveKey(ctx context.Context, issuer string, keyID string) (any, error)
}
