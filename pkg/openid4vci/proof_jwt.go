package openid4vci

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// ProofJWTToken represents a JWT proof token as defined in OpenID4VCI 1.0 Appendix F.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
type ProofJWTToken string

// ProofJWTHeader represents the JOSE header of a JWT proof (Appendix F.1)
type ProofJWTHeader struct {
	// Alg is the algorithm used to sign the JWT, REQUIRED, must not be "none"
	Alg string `json:"alg" validate:"required,ne=none"`

	// Typ is the type of the JWT, REQUIRED, must be "openid4vci-proof+jwt"
	Typ string `json:"typ" validate:"required,eq=openid4vci-proof+jwt"`

	// Kid is the key ID, mutually exclusive with Jwk and X5c
	Kid string `json:"kid,omitempty" validate:"excluded_with=Jwk X5c"`

	// Jwk is the JSON Web Key, mutually exclusive with Kid and X5c
	Jwk *ProofJWK `json:"jwk,omitempty" validate:"excluded_with=Kid X5c"`

	// X5c is the X.509 certificate chain, mutually exclusive with Kid and Jwk
	X5c []string `json:"x5c,omitempty" validate:"excluded_with=Kid Jwk"`
}

// ProofJWTClaims represents the claims of a JWT proof (Appendix F.1)
type ProofJWTClaims struct {
	// Aud is the audience, REQUIRED, must be the Credential Issuer Identifier
	Aud string `json:"aud" validate:"required"`

	// Iat is the issued at time, REQUIRED
	Iat int64 `json:"iat" validate:"required"`

	// Nonce is the c_nonce value, OPTIONAL but REQUIRED when issuer has Nonce Endpoint
	Nonce string `json:"nonce,omitempty"`

	// Iss is the issuer (client_id), OPTIONAL
	Iss string `json:"iss,omitempty"`
}

// ProofJWK represents a JSON Web Key in a proof header
type ProofJWK struct {
	Kty string `json:"kty" validate:"required"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// Validate parses and validates the JWT structure according to OpenID4VCI spec.
// This validates the header and claims structure without verifying the signature.
func (p ProofJWTToken) Validate() error {
	if p == "" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "jwt proof is empty"}
	}

	validate, err := NewValidator()
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to create validator: %v", err)}
	}

	parts := strings.Split(string(p), ".")
	if len(parts) != 3 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "invalid JWT format: expected 3 parts"}
	}

	// Parse and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to decode JWT header: %v", err)}
	}

	var header ProofJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to parse JWT header: %v", err)}
	}

	if err := validate.Struct(&header); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("JWT header validation failed: %v", err)}
	}

	// Check that at least one key binding is present
	if header.Kid == "" && header.Jwk == nil && len(header.X5c) == 0 {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "one of kid, jwk, or x5c must be present in header"}
	}

	// Validate JWK if present (check no private key material)
	if header.Jwk != nil {
		if err := validate.Struct(header.Jwk); err != nil {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("JWK validation failed: %v", err)}
		}
	}

	// Parse and validate claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to decode JWT claims: %v", err)}
	}

	var claims ProofJWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("failed to parse JWT claims: %v", err)}
	}

	if err := validate.Struct(&claims); err != nil {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("JWT claims validation failed: %v", err)}
	}

	return nil
}

// ExtractJWK extracts the holder's public key (JWK) from the JWT header.
// The key can be in the jwk, kid, or x5c header parameter.
func (p ProofJWTToken) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	if p == "" {
		return nil, fmt.Errorf("JWT is empty")
	}

	parts := strings.Split(string(p), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBase64 := parts[0]
	headerByte, err := base64.RawURLEncoding.DecodeString(headerBase64)
	if err != nil {
		// Try standard encoding as fallback
		headerByte, err = base64.RawStdEncoding.DecodeString(headerBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT header: %w", err)
		}
	}

	headerMap := map[string]any{}
	if err := json.Unmarshal(headerByte, &headerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %w", err)
	}

	// Try to extract from jwk header
	if jwkMap, ok := headerMap["jwk"].(map[string]any); ok {
		jwkByte, err := json.Marshal(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JWK: %w", err)
		}

		jwk := &apiv1_issuer.Jwk{}
		if err := json.Unmarshal(jwkByte, jwk); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
		}
		return jwk, nil
	}

	// If kid is present, return a reference JWK (key resolution needed externally)
	if kid, ok := headerMap["kid"].(string); ok {
		return &apiv1_issuer.Jwk{Kid: kid}, nil
	}

	// TODO: Handle x5c (X.509 certificate chain) extraction

	return nil, fmt.Errorf("no key binding found in JWT header (jwk, kid, or x5c required)")
}

// ExtractSubjectDID extracts the subject DID from the JWT claims.
// This looks for an "iss" (issuer) claim which in OpenID4VCI proof JWTs
// typically represents the holder's DID. Returns empty string if not found.
func (p ProofJWTToken) ExtractSubjectDID() string {
	if p == "" {
		return ""
	}

	parts := strings.Split(string(p), ".")
	if len(parts) < 2 {
		return ""
	}

	claimsBase64 := parts[1]
	claimsByte, err := base64.RawURLEncoding.DecodeString(claimsBase64)
	if err != nil {
		// Try standard encoding as fallback
		claimsByte, err = base64.RawStdEncoding.DecodeString(claimsBase64)
		if err != nil {
			return ""
		}
	}

	var claims ProofJWTClaims
	if err := json.Unmarshal(claimsByte, &claims); err != nil {
		return ""
	}

	// The "iss" claim in an OpenID4VCI proof JWT represents the client_id,
	// which for DID-based wallets is typically the holder's DID
	return claims.Iss
}

// ExtractNonce extracts the nonce claim from the JWT proof without verifying signature.
func (p ProofJWTToken) ExtractNonce() string {
	if p == "" {
		return ""
	}

	parts := strings.Split(string(p), ".")
	if len(parts) < 2 {
		return ""
	}

	claimsByte, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		claimsByte, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsByte, &claims); err != nil {
		return ""
	}

	if nonce, ok := claims["nonce"].(string); ok {
		return nonce
	}
	return ""
}

// Verify verifies a JWT proof according to OpenID4VCI 1.0 Appendix F.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
func (p ProofJWTToken) Verify(publicKey crypto.PublicKey, opts *VerifyProofOptions) error {
	// First validate the JWT structure using validator tags
	if err := p.Validate(); err != nil {
		return err
	}

	claims := jwtv5.MapClaims{}

	token, err := jwtv5.ParseWithClaims(string(p), claims, func(token *jwtv5.Token) (any, error) {
		// Check if algorithm is supported (runtime option, not covered by struct validation)
		if opts != nil && len(opts.SupportedAlgorithms) > 0 {
			alg, ok := token.Header["alg"].(string)
			if !ok {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg header must be a string"}
			}
			if !slices.Contains(opts.SupportedAlgorithms, alg) {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("alg '%s' is not supported", alg)}
			}
		}

		// Validate that jwk does not contain a private key (d parameter)
		if jwkMap, ok := token.Header["jwk"].(map[string]any); ok {
			if _, hasD := jwkMap["d"]; hasD {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "jwk must not contain private key material (d parameter)"}
			}
		}

		// Runtime validations that depend on opts or current time

		// aud: validate against expected audience if provided
		if opts != nil && opts.Audience != "" {
			aud, err := claims.GetAudience()
			if err != nil {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse aud claim"}
			}
			if !slices.Contains(aud, opts.Audience) {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "aud claim does not match expected audience"}
			}
		}

		// iat: validate not in the future
		t, err := claims.GetIssuedAt()
		if err != nil {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "failed to parse iat claim"}
		}
		if t.After(time.Now()) {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat claim value is in the future"}
		}

		// nonce: validate against server-provided c_nonce if provided
		if opts != nil && opts.CNonce != "" {
			nonce, ok := claims["nonce"]
			if !ok {
				return nil, &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim not found but c_nonce was provided"}
			}
			if nonce != opts.CNonce {
				return nil, &Error{Err: ErrInvalidNonce, ErrorDescription: "nonce claim does not match server-provided c_nonce"}
			}
		}

		// Validate signing method - must be asymmetric algorithm
		switch token.Method.(type) {
		case *jwtv5.SigningMethodECDSA:
			// ES256, ES384, ES512
		case *jwtv5.SigningMethodRSA:
			// RS256, RS384, RS512
		case *jwtv5.SigningMethodRSAPSS:
			// PS256, PS384, PS512
		case *jwtv5.SigningMethodEd25519:
			// EdDSA
		default:
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("unsupported signing method: %v", token.Header["alg"])}
		}

		return publicKey, nil
	})
	if err != nil {
		// If the error is already an OpenID4VCI error (from keyFunc), return it as-is
		var vciErr *Error
		if errors.As(err, &vciErr) {
			return vciErr
		}
		// Wrap JWT library errors (signature verification failures, etc.) as invalid_proof
		return &Error{Err: ErrInvalidProof, ErrorDescription: err.Error()}
	}

	if !token.Valid {
		return &Error{Err: ErrInvalidProof, ErrorDescription: "JWT signature is invalid"}
	}

	return nil
}
