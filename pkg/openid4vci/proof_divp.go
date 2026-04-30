package openid4vci

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
)

// ProofDIVP represents a W3C Verifiable Presentation with Data Integrity Proof
// as defined in OpenID4VCI 1.0 Appendix F.2
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type
type ProofDIVP struct {
	// Context is the JSON-LD context, REQUIRED per W3C VC Data Model
	Context []string `json:"@context" validate:"required,min=1"`

	// Type is the type of the presentation, REQUIRED, must include "VerifiablePresentation"
	Type []string `json:"type" validate:"required,min=1"`

	// Proof contains the Data Integrity Proof(s), one of Proof or Proofs REQUIRED
	Proof *DIVPProof `json:"proof,omitempty" validate:"required_without=Proofs"`

	// Proofs contains multiple Data Integrity Proofs if more than one is present
	Proofs []DIVPProof `json:"proofs,omitempty" validate:"required_without=Proof,dive"`

	// VerifiableCredential contains the credentials being presented
	VerifiableCredential []any `json:"verifiableCredential,omitempty"`

	// Holder is the DID of the holder
	Holder string `json:"holder,omitempty"`

	// ID is an optional identifier for the presentation
	ID string `json:"id,omitempty"`
}

// Validate validates the ProofDIVP struct using validator tags.
func (vp *ProofDIVP) Validate() error {
	validate, err := NewValidator()
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to create validator: %v", err)}
	}

	// Validate the struct using validator tags
	if err := validate.Struct(vp); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("di_vp proof validation failed: %v", err)}
	}

	// Additional validation: Type must include "VerifiablePresentation"
	if !slices.Contains(vp.Type, "VerifiablePresentation") {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "type must include 'VerifiablePresentation'"}
	}

	return nil
}

// DIVPProof represents a Data Integrity Proof
// https://www.w3.org/TR/vc-data-integrity/
type DIVPProof struct {
	// Type is the proof type, e.g., "DataIntegrityProof"
	Type string `json:"type" validate:"required"`

	// Cryptosuite identifies the cryptographic suite used
	// Supported: eddsa-rdfc-2022, ecdsa-rdfc-2019, ecdsa-sd-2023, eddsa-jcs-2022, ecdsa-jcs-2019
	Cryptosuite string `json:"cryptosuite" validate:"required,oneof=eddsa-rdfc-2022 ecdsa-rdfc-2019 ecdsa-sd-2023 eddsa-jcs-2022 ecdsa-jcs-2019"`

	// ProofPurpose MUST be "authentication" for OpenID4VCI
	ProofPurpose string `json:"proofPurpose" validate:"required,eq=authentication"`

	// VerificationMethod is a URL that identifies the public key to use for verification
	VerificationMethod string `json:"verificationMethod" validate:"required"`

	// Domain MUST be the Credential Issuer Identifier
	Domain string `json:"domain" validate:"required"`

	// Challenge MUST be the c_nonce value provided by the Credential Issuer (when provided)
	Challenge string `json:"challenge,omitempty"`

	// Created is the creation time of the proof
	Created string `json:"created,omitempty"`

	// ProofValue is the actual proof signature value
	ProofValue string `json:"proofValue" validate:"required"`
}

// ExtractJWK extracts the holder's public key reference from the DI_VP proof.
// For DI_VP, the verificationMethod is typically a DID URL that needs external resolution.
// This method returns a JWK with the Kid set to the verificationMethod for external resolution.
func (vp *ProofDIVP) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	// Collect proofs from either single proof or proofs array
	var proofs []DIVPProof
	if vp.Proof != nil {
		proofs = append(proofs, *vp.Proof)
	}
	proofs = append(proofs, vp.Proofs...)

	if len(proofs) == 0 {
		return nil, fmt.Errorf("no proof found in di_vp")
	}

	// Get the verificationMethod from the first proof
	verificationMethod := proofs[0].VerificationMethod
	if verificationMethod == "" {
		return nil, fmt.Errorf("verificationMethod not found in di_vp proof")
	}

	// Return a JWK reference with Kid set to the verificationMethod
	// The actual key resolution from DID needs to be done externally
	return &apiv1_issuer.Jwk{
		Kid: verificationMethod,
	}, nil
}

// Verify verifies a Data Integrity Verifiable Presentation proof
// according to OpenID4VCI 1.0 Appendix F.2
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type
func (vp *ProofDIVP) Verify(opts *VerifyProofOptions) error {
	// First validate the struct using validator tags
	if err := vp.Validate(); err != nil {
		return err
	}

	// Collect proofs from either single proof or proofs array
	var proofs []DIVPProof
	if vp.Proof != nil {
		proofs = append(proofs, *vp.Proof)
	}
	proofs = append(proofs, vp.Proofs...)

	// Runtime validations that depend on opts
	for _, proof := range proofs {
		// domain: validate against expected audience if provided
		if opts != nil && opts.Audience != "" {
			if proof.Domain != opts.Audience {
				return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "domain does not match expected Credential Issuer Identifier"}
			}
		}

		// challenge: validate against server-provided c_nonce if provided
		if opts != nil && opts.CNonce != "" {
			if proof.Challenge == "" {
				return &Error{Err: ErrInvalidNonce, ErrorDescription: "challenge is required in proof when c_nonce is provided"}
			}
			if proof.Challenge != opts.CNonce {
				return &Error{Err: ErrInvalidNonce, ErrorDescription: "challenge does not match server-provided c_nonce"}
			}
		}
	}

	// TODO: Implement actual cryptographic verification of the Data Integrity Proof
	// This requires implementing the specific cryptosuite verification logic

	return nil
}
