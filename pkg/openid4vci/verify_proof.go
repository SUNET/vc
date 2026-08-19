package openid4vci

import (
	"crypto"
)

// VerifyProofOptions contains optional parameters for proof verification
type VerifyProofOptions struct {
	// CNonce is the server-provided nonce value that must match the nonce in the proof
	// Required when the Credential Issuer has a Nonce Endpoint
	CNonce string
	// Audience is the expected Credential Issuer Identifier (required for aud validation)
	Audience string
	// SupportedAlgorithms is a list of supported signing algorithms
	SupportedAlgorithms []string
}

// VerifyProof verifies the key proof according to OpenID4VCI 1.0 Appendix F.4
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-verifying-proof
//
// To validate a key proof, the Credential Issuer MUST ensure that:
// - all required claims for that proof type are contained
// - the key proof is explicitly typed using header parameters
// - the header parameter indicates a registered asymmetric digital signature algorithm, not "none"
// - the signature on the key proof verifies with the public key
// - the header parameter does not contain a private key
// - if the server has a Nonce Endpoint, the nonce matches the server-provided c_nonce
// - the creation time is within an acceptable window
func (c *CredentialRequest) VerifyProof(publicKey crypto.PublicKey) error {
	return c.VerifyProofWithOptions(publicKey, nil)
}

// VerifyProofWithOptions verifies the key proof with additional options.
// Supports jwt, di_vp, and attestation proof types as defined in the OpenID4VCI spec.
func (c *CredentialRequest) VerifyProofWithOptions(publicKey crypto.PublicKey, opts *VerifyProofOptions) error {
	if c.Proofs == nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "proofs is required"}
	}

	// Count how many proof types are provided - only one should be used
	proofTypeCount := 0
	if len(c.Proofs.JWT) > 0 {
		proofTypeCount++
	}
	if len(c.Proofs.DIVP) > 0 {
		proofTypeCount++
	}
	if len(c.Proofs.Attestation) > 0 {
		proofTypeCount++
	}

	if proofTypeCount == 0 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "at least one proof type (jwt, di_vp, or attestation) is required in proofs"}
	}

	if proofTypeCount > 1 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "only one proof type should be used per request"}
	}

	// Verify JWT proofs
	if len(c.Proofs.JWT) > 0 {
		for _, jwtProof := range c.Proofs.JWT {
			if err := jwtProof.Verify(publicKey, opts); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify DI_VP proofs
	if len(c.Proofs.DIVP) > 0 {
		for i := range c.Proofs.DIVP {
			if err := c.Proofs.DIVP[i].Verify(opts); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify Attestation proofs
	if len(c.Proofs.Attestation) > 0 {
		for _, attestationProof := range c.Proofs.Attestation {
			if err := attestationProof.Verify(opts); err != nil {
				return err
			}
		}
		return nil
	}

	return nil
}
