// Package trustapi provides common interfaces and types for trust evaluation.
//
// This package defines the contract between trust evaluation consumers (verifiers,
// issuers, wallets) and providers (go-trust PDP, local trust anchors). It does not
// include implementations - those live in the consuming applications.
//
// Key concepts:
//   - TrustEvaluator: Evaluates whether a name-to-key binding is trusted
//   - KeyResolver: Resolves public keys from identifiers (DIDs, URLs)
//   - EvaluationRequest: Contains subject, key, and optional role/context
//   - TrustDecision: The evaluation result with reason and metadata
//
// This package is intentionally minimal to avoid coupling go-trust to specific
// credential formats or application concerns.
package trustapi

import (
	"crypto/x509"
	"encoding/base64"
)

// KeyType indicates the format of the public key being validated.
type KeyType string

const (
	// KeyTypeJWK indicates a JWK (JSON Web Key) format key.
	KeyTypeJWK KeyType = "jwk"
	// KeyTypeX5C indicates an X.509 certificate chain.
	KeyTypeX5C KeyType = "x5c"
)

// Role represents the expected role of the key holder.
// These are common roles; applications may define additional roles.
type Role string

const (
	// RoleIssuer indicates the key should be authorized for credential issuance.
	RoleIssuer Role = "issuer"
	// RoleVerifier indicates the key should be authorized for credential verification.
	RoleVerifier Role = "verifier"
	// RoleWalletProvider indicates the key is for a wallet provider.
	RoleWalletProvider Role = "wallet_provider"
	// RolePIDProvider indicates the key is for a PID (Person Identification Data) provider.
	RolePIDProvider Role = "pid-provider"
	// RoleCredentialIssuer indicates an OpenID4VCI credential issuer.
	RoleCredentialIssuer Role = "credential-issuer"
	// RoleCredentialVerifier indicates an OpenID4VP credential verifier.
	RoleCredentialVerifier Role = "credential-verifier"
	// RoleStatusListSigner indicates the key signs an IETF Token Status List.
	// The signer is not necessarily the credential issuer, so it is evaluated
	// as its own AuthZEN action.name.
	RoleStatusListSigner Role = "status-list-signer"
	// RoleEMRTDDocumentSigner indicates the key is an ICAO 9303 eMRTD Document
	// Signer Certificate (DSC) that must chain to a trusted CSCA of the
	// claimed issuing state.
	RoleEMRTDDocumentSigner Role = "emrtd-document-signer"
	// RoleAny indicates no specific role constraint.
	RoleAny Role = ""
)

// EvaluationRequest contains the parameters for a trust evaluation.
type EvaluationRequest struct {
	// SubjectID is the identifier of the entity (DID, issuer URL, etc.).
	SubjectID string

	// KeyType indicates the format of the key.
	KeyType KeyType

	// Key is the public key to validate. Can be:
	//   - map[string]any for JWK
	//   - []*x509.Certificate for x5c
	//   - crypto.PublicKey for raw keys
	Key any

	// Role is the expected role (optional). Implementations may map this
	// to action.name when using AuthZEN, enabling policy-based routing.
	Role Role

	// Action is an explicit policy name to use (optional).
	// If set, this takes precedence over Role.
	Action string

	// CredentialType is the type of credential (e.g., "PID", "mDL", "VerifiableCredential").
	// This can influence policy selection when combined with Role.
	CredentialType string

	// DocType is the ISO mDOC document type (for mDOC credentials).
	DocType string

	// Options contains additional trust evaluation options.
	Options *TrustOptions
}

// TrustOptions contains additional options for trust evaluation.
type TrustOptions struct {
	// IncludeTrustChain requests the full trust chain in the response.
	IncludeTrustChain bool

	// IncludeCertificates requests X.509 certificates in the response.
	IncludeCertificates bool

	// BypassCache requests that cached results be bypassed.
	BypassCache bool
}

// TrustDecision represents the result of a trust evaluation.
type TrustDecision struct {
	// Trusted indicates whether the name-to-key binding is authorized.
	Trusted bool

	// Reason provides explanation for the decision.
	Reason string

	// TrustFramework identifies which trust framework was used (e.g., "eudi", "openid_federation").
	TrustFramework string

	// Metadata contains additional trust metadata (e.g., DID document, entity configuration).
	Metadata any
}

// X5CCertChain is a helper type for x5c certificate chains.
type X5CCertChain []*x509.Certificate

// GetLeafCert returns the end-entity certificate (first in chain).
func (c X5CCertChain) GetLeafCert() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[0]
}

// GetRootCert returns the root certificate (last in chain).
func (c X5CCertChain) GetRootCert() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[len(c)-1]
}

// GetSubjectID extracts a subject identifier from the leaf certificate.
// Returns the Subject CN or the first SAN URI/DNS name.
func (c X5CCertChain) GetSubjectID() string {
	leaf := c.GetLeafCert()
	if leaf == nil {
		return ""
	}

	// Try Subject CN first
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}

	// Try SAN URIs
	for _, uri := range leaf.URIs {
		return uri.String()
	}

	// Try SAN DNS names
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}

	return ""
}

// ToBase64Strings converts the certificate chain to base64-encoded DER strings.
// This is the format expected by JWK x5c arrays and AuthZEN x5c resources.
func (c X5CCertChain) ToBase64Strings() []string {
	result := make([]string, len(c))
	for i, cert := range c {
		result[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return result
}
