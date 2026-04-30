package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// ProofAttestation represents a Key Attestation JWT proof as defined in OpenID4VCI 1.0 Appendix D.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation
type ProofAttestation string

// ProofAttestationHeader represents the JOSE header of a Key Attestation JWT (Appendix D.1)
type ProofAttestationHeader struct {
	// Alg is the algorithm used to sign the JWT, REQUIRED, must not be "none"
	Alg string `json:"alg" validate:"required,ne=none"`

	// Typ is the type of the JWT, REQUIRED, must be "key-attestation+jwt"
	Typ string `json:"typ" validate:"required,eq=key-attestation+jwt"`

	// Kid is the key ID of the attestation issuer's signing key
	Kid string `json:"kid,omitempty"`

	// X5c is the X.509 certificate chain of the attestation issuer
	X5c []string `json:"x5c,omitempty"`
}

// ProofAttestationClaims represents the claims of a Key Attestation JWT (Appendix D.1)
type ProofAttestationClaims struct {
	// Iss is the issuer of the attestation, OPTIONAL
	Iss string `json:"iss,omitempty"`

	// Iat is the issued at time, REQUIRED
	Iat int64 `json:"iat" validate:"required"`

	// Exp is the expiration time, OPTIONAL
	Exp int64 `json:"exp,omitempty"`

	// AttestedKeys is a non-empty array of attested JWKs, REQUIRED
	AttestedKeys []ProofJWK `json:"attested_keys" validate:"required,min=1,dive"`

	// Nonce is the c_nonce value, OPTIONAL but REQUIRED when issuer has Nonce Endpoint
	Nonce string `json:"nonce,omitempty"`

	// AttestationProcess describes the attestation process, OPTIONAL
	AttestationProcess string `json:"attestation_process,omitempty"`
}

// Validate parses and validates the Key Attestation JWT structure according to OpenID4VCI spec.
// This validates the header and claims structure without verifying the signature.
func (p ProofAttestation) Validate() error {
	if p == "" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "attestation proof is empty"}
	}

	validate, err := NewValidator()
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to create validator: %v", err)}
	}

	parts := strings.Split(string(p), ".")
	if len(parts) != 3 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "invalid attestation JWT format: expected 3 parts"}
	}

	// Parse and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to decode attestation header: %v", err)}
	}

	var header ProofAttestationHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to parse attestation header: %v", err)}
	}

	if err := validate.Struct(&header); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("attestation header validation failed: %v", err)}
	}

	// Parse and validate claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to decode attestation claims: %v", err)}
	}

	var claims ProofAttestationClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to parse attestation claims: %v", err)}
	}

	if err := validate.Struct(&claims); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("attestation claims validation failed: %v", err)}
	}

	return nil
}

// ExtractJWK extracts the first attested key (JWK) from the attestation JWT.
// The attested_keys claim contains an array of JWKs that are attested by this proof.
func (p ProofAttestation) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	if p == "" {
		return nil, fmt.Errorf("attestation is empty")
	}

	token, _, err := jwtv5.NewParser().ParseUnverified(string(p), jwtv5.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation JWT: %w", err)
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from attestation JWT")
	}

	attestedKeys, ok := claims["attested_keys"]
	if !ok {
		return nil, fmt.Errorf("attested_keys claim not found in attestation")
	}

	keysArr, ok := attestedKeys.([]any)
	if !ok || len(keysArr) == 0 {
		return nil, fmt.Errorf("attested_keys must be a non-empty array")
	}

	// Extract the first key
	firstKey, ok := keysArr[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("first attested key is not a valid JWK object")
	}

	jwkByte, err := json.Marshal(firstKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	jwk := &apiv1_issuer.Jwk{}
	if err := json.Unmarshal(jwkByte, jwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	return jwk, nil
}

// Verify verifies a Key Attestation proof according to OpenID4VCI 1.0 Appendix D.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation
func (p ProofAttestation) Verify(opts *VerifyProofOptions) error {
	// First validate the JWT structure using validator tags
	if err := p.Validate(); err != nil {
		return err
	}

	token, _, err := jwtv5.NewParser().ParseUnverified(string(p), jwtv5.MapClaims{})
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse attestation JWT"}
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to extract claims from attestation JWT"}
	}

	// Runtime validations that depend on opts

	// Check if algorithm is supported (if supported algorithms are specified)
	if opts != nil && len(opts.SupportedAlgorithms) > 0 {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg header must be a string"}
		}
		if !slices.Contains(opts.SupportedAlgorithms, alg) {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("alg '%s' is not supported", alg)}
		}
	}

	// nonce: validate against server-provided c_nonce if provided
	if opts != nil && opts.CNonce != "" {
		nonce, ok := claims["nonce"]
		if !ok {
			return &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim not found in attestation but c_nonce was provided"}
		}
		if nonce != opts.CNonce {
			return &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim does not match server-provided c_nonce"}
		}
	}

	// TODO: Implement signature verification against trusted attestation issuers
	// This requires establishing trust in the attestation issuer

	return nil
}
