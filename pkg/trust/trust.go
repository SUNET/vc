// Package trust provides a unified trust evaluation interface for all credential formats.
//
// This package bridges the gap between different credential formats' trust models:
//   - W3C VC 2.0 Data Integrity: uses DIDs for key identification
//   - SD-JWT VC: uses x5c certificate chains with issuer URLs
//   - ISO mDOC: uses IACA certificate chains with document signer certificates
//
// The key distinction is between:
//   - Name-to-key RESOLUTION: Given a name (DID), fetch the associated public key
//   - Name-to-key VALIDATION: Given a name and key, verify the binding is trusted
//
// When DIDs are used, go-trust can perform resolution. When certificates are used
// (SD-JWT x5c, mDOC MSO), the key is already present, so only validation is needed.
//
// This package uses types from github.com/sirosfoundation/go-trust/pkg/trustapi
// and adds vc-specific logic like GetEffectiveAction() for policy routing.
package trust

import (
	"context"
	"crypto"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// Type aliases from trustapi for compatibility and convenience.
// These allow existing code to continue using trust.EvaluationRequest etc.
type (
	// TrustDecision represents the result of a trust evaluation.
	TrustDecision = trustapi.TrustDecision

	// KeyType indicates the format of the public key being validated.
	KeyType = trustapi.KeyType

	// Role represents the expected role of the key holder.
	Role = trustapi.Role

	// TrustOptions contains additional options for trust evaluation.
	TrustOptions = trustapi.TrustOptions

	// X5CCertChain is a helper type for x5c certificate chains.
	X5CCertChain = trustapi.X5CCertChain
)

// Constants re-exported from trustapi for convenience.
const (
	KeyTypeJWK = trustapi.KeyTypeJWK
	KeyTypeX5C = trustapi.KeyTypeX5C

	RoleIssuer             = trustapi.RoleIssuer
	RoleVerifier           = trustapi.RoleVerifier
	RoleWalletProvider     = trustapi.RoleWalletProvider
	RolePIDProvider        = trustapi.RolePIDProvider
	RoleCredentialIssuer   = trustapi.RoleCredentialIssuer
	RoleCredentialVerifier = trustapi.RoleCredentialVerifier
	RoleAny                = trustapi.RoleAny
)

// TrustFramework constants for common trust framework identifiers.
const (
	// TrustFrameworkNone indicates no trust framework validation occurred.
	// Used by AllowAllEvaluator when operating without a PDP.
	TrustFrameworkNone = "none"
)

// Error messages for trust evaluation. These are package-level constants
// to ensure consistency across evaluator implementations.
const (
	// ErrMsgNilRequest is returned when an evaluation request is nil.
	ErrMsgNilRequest = "evaluation request is nil"
)

// EvaluationRequest contains the parameters for a trust evaluation.
// This embeds trustapi.EvaluationRequest and adds vc-specific methods.
type EvaluationRequest struct {
	trustapi.EvaluationRequest
}

// GetEffectiveAction returns the action name to use for policy routing.
// Priority: 1. Explicit Action field, 2. Composed from Role + CredentialType/DocType, 3. Role alone
//
// This is vc-specific logic that maps credential types to go-trust policy names.
func (r *EvaluationRequest) GetEffectiveAction() string {
	// If explicit action is set, use it
	if r.Action != "" {
		return r.Action
	}

	// If no role, no action
	if r.Role == "" {
		return ""
	}

	// For PID credentials with issuer role, use pid-provider policy
	if r.CredentialType == "PID" && r.Role == RoleIssuer {
		return string(RolePIDProvider)
	}

	// For mDL documents, use mDL-specific policy
	if r.DocType == "org.iso.18013.5.1.mDL" {
		if r.Role == RoleIssuer || r.Role == RoleCredentialIssuer {
			return "mdl-issuer"
		}
		if r.Role == RoleVerifier || r.Role == RoleCredentialVerifier {
			return "mdl-verifier"
		}
	}

	// For credential issuers, use credential-issuer policy
	if (r.Role == RoleIssuer || r.Role == RoleCredentialIssuer) && (r.CredentialType != "" || r.DocType != "") {
		return string(RoleCredentialIssuer)
	}

	// For verifiers, use credential-verifier policy
	if r.Role == RoleVerifier || r.Role == RoleCredentialVerifier {
		return string(RoleCredentialVerifier)
	}

	// Fall back to role
	return string(r.Role)
}

// TrustEvaluator evaluates whether a name-to-key binding is trusted.
// This extends trustapi.TrustEvaluator to work with our EvaluationRequest.
type TrustEvaluator interface {
	// Evaluate checks if the given key is trusted for the specified subject and role.
	// This is used when the key is already known (SD-JWT x5c, mDOC certificates).
	Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)

	// SupportsKeyType returns true if this evaluator can handle the given key type.
	SupportsKeyType(kt KeyType) bool
}

// KeyResolver resolves public keys from identifiers.
// This is used when the key needs to be fetched (DID-based credentials).
type KeyResolver interface {
	// ResolveKey retrieves the public key for the given verification method.
	ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// CombinedTrustService combines evaluation and resolution capabilities.
// This is the full interface for trust management across all credential formats.
type CombinedTrustService interface {
	TrustEvaluator
	KeyResolver
}

// NewEvaluationRequest creates a new EvaluationRequest with the given parameters.
// This is a convenience constructor.
func NewEvaluationRequest(subjectID string, keyType KeyType, key any) *EvaluationRequest {
	return &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: subjectID,
			KeyType:   keyType,
			Key:       key,
		},
	}
}
