package openid4vci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	"github.com/golang-jwt/jwt/v5"
)

// HashAuthorizeToken hashes the Authorization header using SHA-256 and encodes it in Base64 URL format.
func (c *CredentialRequest) HashAuthorizeToken() string {
	token := strings.TrimPrefix(c.Authorization, "DPoP ")

	tokenS256 := sha256.Sum256([]byte(token))

	b64 := base64.RawURLEncoding.EncodeToString(tokenS256[:])
	return b64
}

// CredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
type CredentialRequest struct {
	// Header fields
	DPoP          string `header:"dpop" validate:"required"`
	Authorization string `header:"Authorization" validate:"required"`

	// CredentialIdentifier REQUIRED when an Authorization Details of type openid_credential was returned
	// from the Token Response. It MUST NOT be used otherwise. A string that identifies a Credential Dataset
	// that is requested for issuance. When this parameter is used, the credential_configuration_id MUST NOT be present.
	CredentialIdentifier string `json:"credential_identifier,omitempty" validate:"required_without=CredentialConfigurationID,excluded_with=CredentialConfigurationID"`

	// CredentialConfigurationID REQUIRED if a credential_identifiers parameter was not returned from
	// the Token Response as part of the authorization_details parameter. It MUST NOT be used otherwise.
	// String that uniquely identifies one of the keys in the name/value pairs stored in the
	// credential_configurations_supported Credential Issuer metadata. When this parameter is used,
	// the credential_identifier MUST NOT be present.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty" validate:"required_without=CredentialIdentifier,excluded_with=CredentialIdentifier"`

	// Proofs OPTIONAL. Object providing one or more proof of possessions of the cryptographic key material
	// to which the issued Credential instances will be bound to. The proofs parameter contains exactly one
	// parameter named as the proof type in Appendix F, the value set for this parameter is a non-empty array
	// containing parameters as defined by the corresponding proof type.
	Proofs *Proofs `json:"proofs,omitempty" validate:"omitempty"`

	// Proof OPTIONAL. Single proof object for non-batch requests.
	// Deprecated: Use Proofs instead. This field is kept for backward compatibility with older wallets.
	Proof *Proof `json:"proof,omitempty" validate:"omitempty"`

	// CredentialResponseEncryption OPTIONAL. Object containing information for encrypting the Credential Response.
	// If this request element is not present, the corresponding credential response returned is not encrypted.
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty" validate:"omitempty"`
}

// IsAccessTokenDPoP checks if the Authorization header belongs to DPoP proof
func (c *CredentialRequest) IsAccessTokenDPoP() bool {
	return strings.HasPrefix(c.Authorization, "DPoP ")
}

// Validate validates the CredentialRequest against the authorization details per OID4VCI 1.0 Section 7.1.
// When authorization_details with credential_identifiers was returned in the Token Response,
// the Credential Request MUST use credential_identifier (matching one of the returned identifiers).
// Otherwise, credential_configuration_id MUST be used.
func (c *CredentialRequest) Validate(ctx context.Context, authorizationDetails []AuthorizationDetailsParameter) error {
	hasAuthDetails := len(authorizationDetails) > 0

	// Neither identifier nor configuration ID provided
	if c.CredentialIdentifier == "" && c.CredentialConfigurationID == "" {
		if hasAuthDetails {
			return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "credential_identifier is required when authorization_details was returned in the Token Response"}
		}
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "credential_configuration_id is required when authorization_details was not returned in the Token Response"}
	}

	// Both provided simultaneously
	if c.CredentialIdentifier != "" && c.CredentialConfigurationID != "" {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "credential_identifier and credential_configuration_id must not both be present"}
	}

	// credential_identifier provided: verify it matches the Token Response
	if c.CredentialIdentifier != "" {
		if !hasAuthDetails {
			return &Error{Err: ErrUnknownCredentialIdentifier, ErrorDescription: fmt.Sprintf("credential_identifier %q cannot be resolved: no authorization_details in Token Response", c.CredentialIdentifier)}
		}
		for _, ad := range authorizationDetails {
			if slices.Contains(ad.CredentialIdentifiers, c.CredentialIdentifier) {
				return nil
			}
		}
		return &Error{Err: ErrUnknownCredentialIdentifier, ErrorDescription: fmt.Sprintf("credential_identifier %q not found in Token Response authorization_details", c.CredentialIdentifier)}
	}

	// credential_configuration_id provided without authorization_details: allowed
	if hasAuthDetails {
		return &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "credential_configuration_id must not be used when authorization_details was returned in the Token Response; use credential_identifier instead"}
	}
	return nil
}

// CredentialResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialResponse struct {
	// Credentials OPTIONAL. Contains an array of issued Credentials. It MUST NOT be used if credential or transaction_id parameter is present. The values in the array MAY be a string or an object, depending on the Credential Format. See Appendix A for the Credential Format-specific encoding requirements.
	Credentials []Credential `json:"credentials,omitempty" validate:"required_without=TransactionID Credential"`

	// TransactionID: OPTIONAL. String identifying a Deferred Issuance transaction. This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint (see Section 9). It MUST be present when the credential parameter is not returned. It MUST be invalidated after the Credential for which it was meant has been obtained by the Wallet.
	TransactionID string `json:"transaction_id,omitempty" validate:"required_without=Credentials Credential"`

	// CNonce: OPTIONAL. String containing a nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent Credential Requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn: OPTIONAL. Number denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	// NotificationID: OPTIONAL. String identifying an issued Credential that the Wallet includes in the Notification Request as defined in Section 10.1. This parameter MUST NOT be present if credential parameter is not present.
	NotificationID string `json:"notification_id,omitempty" validate:"required_with=Credentials"`
}

type Credential struct {
	Credential string `json:"credential" validate:"required"`
}

// ProofJWT holds the JWT for proof
type ProofJWT struct {
	jwt.RegisteredClaims
}

// JWK holds the JSON Web Key
type JWK struct {
	CRV string `json:"crv" validate:"required"`
	KID string `json:"kid" validate:"required"`
	KTY string `json:"kty" validate:"required"`
	X   string `json:"x" validate:"required"`
	Y   string `json:"y" validate:"required"`
}

// Proof represents a single proof object (used in non-batch requests)
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
type Proof struct {
	// ProofType REQUIRED. String denoting the key proof type.
	ProofType string `json:"proof_type" validate:"required"`

	// JWT The JWT proof, when proof_type is "jwt"
	JWT string `json:"jwt,omitempty"`

	// CWT The CWT proof, when proof_type is "cwt"
	CWT string `json:"cwt,omitempty"`

	// LDPVp The Linked Data Proof VP, when proof_type is "ldp_vp"
	LDPVp any `json:"ldp_vp,omitempty"`
}

// ExtractJWK extracts the holder's public key from the proof
func (p *Proof) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	switch p.ProofType {
	case "jwt":
		if p.JWT == "" {
			return nil, fmt.Errorf("jwt proof is empty")
		}
		token := ProofJWTToken(p.JWT)
		return token.ExtractJWK()
	default:
		return nil, fmt.Errorf("unsupported proof type: %s", p.ProofType)
	}
}

// ExtractSubjectDID extracts the subject DID from the proof if available.
// For JWT proofs, this would typically come from the JWT claims.
// Returns empty string if no subject DID is found.
func (p *Proof) ExtractSubjectDID() string {
	switch p.ProofType {
	case "jwt":
		if p.JWT == "" {
			return ""
		}
		token := ProofJWTToken(p.JWT)
		return token.ExtractSubjectDID()
	default:
		return ""
	}
}

// Proofs https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
// Contains arrays of proofs by type for batch credential requests.
// Only one proof type should be used per request.
type Proofs struct {
	// JWT contains an array of JWTs as defined in Appendix F.1
	JWT []ProofJWTToken `json:"jwt,omitempty"`

	// DIVP contains an array of W3C Verifiable Presentations
	// signed using Data Integrity Proof as defined in Appendix F.2
	DIVP []ProofDIVP `json:"di_vp,omitempty"`

	// Attestation contains a single JWT representing a key attestation
	// as defined in Appendix D.1
	Attestation ProofAttestation `json:"attestation,omitempty"`
}

// ExtractJWK extracts the holder's public key (JWK) from the proofs.
// It automatically detects which proof type is present and extracts accordingly:
// - jwt: from the jwk header of the first JWT
// - di_vp: from the verificationMethod of the first proof
// - attestation: from the attested_keys claim
func (p *Proofs) ExtractJWK() (*apiv1_issuer.Jwk, error) {
	// Check which proof type is present and extract accordingly
	if len(p.JWT) > 0 {
		return p.JWT[0].ExtractJWK()
	}

	if len(p.DIVP) > 0 {
		return p.DIVP[0].ExtractJWK()
	}

	if p.Attestation != "" {
		return p.Attestation.ExtractJWK()
	}

	return nil, fmt.Errorf("no proofs found")
}

// CredentialResponseEncryption contains information for encrypting the Credential Response.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
type CredentialResponseEncryption struct {
	// JWK REQUIRED. Object containing a single public key as a JWK used for encrypting the Credential Response.
	JWK JWK `json:"jwk" validate:"required"`

	// Enc REQUIRED. JWE enc algorithm for encrypting Credential Responses.
	Enc string `json:"enc" validate:"required"`

	// Zip OPTIONAL. JWE zip algorithm for compressing Credential Responses prior to encryption.
	// If absent then compression MUST not be used.
	Zip string `json:"zip,omitempty"`
}

// ResolveCredentialFormat determines the credential format from the request.
// According to OpenID4VCI spec, the format is derived from the credential_configuration_id
// which maps to a credential configuration in the issuer metadata.
//
// Deprecated: Use ResolveCredentialFormatWithAuthDetails for credential_identifier support.
func (req *CredentialRequest) ResolveCredentialFormat(metadata *CredentialIssuerMetadataParameters) (string, error) {
	return req.ResolveCredentialFormatWithAuthDetails(metadata, nil)
}

// ResolveCredentialFormatWithAuthDetails determines the credential format from the request.
// When credential_identifier is used, the authorizationDetails from the token response
// are needed to map the identifier to a credential_configuration_id.
func (req *CredentialRequest) ResolveCredentialFormatWithAuthDetails(metadata *CredentialIssuerMetadataParameters, authorizationDetails []AuthorizationDetailsParameter) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("metadata is required")
	}

	// Use credential_configuration_id to look up the format from issuer metadata
	if req.CredentialConfigurationID != "" {
		if metadata.CredentialConfigurationsSupported != nil {
			if config, ok := metadata.CredentialConfigurationsSupported[req.CredentialConfigurationID]; ok {
				return config.Format, nil
			}
		}
		return "", &Error{Err: ErrUnknownCredentialConfiguration, ErrorDescription: fmt.Sprintf("unknown credential_configuration_id: %s", req.CredentialConfigurationID)}
	}

	// Use credential_identifier to look up the format via authorization_details.
	// The credential_identifier maps to a credential_configuration_id in the
	// authorization_details that were returned in the token response.
	if req.CredentialIdentifier != "" {
		for _, ad := range authorizationDetails {
			if slices.Contains(ad.CredentialIdentifiers, req.CredentialIdentifier) {
				// Format-based authorization_details: the entry carries Format directly
				// instead of CredentialConfigurationID (OID4VCI §5.1.1).
				if ad.CredentialConfigurationID == "" && ad.Format != "" {
					return ad.Format, nil
				}
				if metadata.CredentialConfigurationsSupported != nil {
					if config, ok := metadata.CredentialConfigurationsSupported[ad.CredentialConfigurationID]; ok {
						return config.Format, nil
					}
				}
				return "", &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: fmt.Sprintf("credential_configuration_id %q from authorization_details not found in issuer metadata", ad.CredentialConfigurationID)}
			}
		}
		return "", &Error{Err: ErrUnknownCredentialIdentifier, ErrorDescription: fmt.Sprintf("could not resolve credential_identifier %q to a credential configuration", req.CredentialIdentifier)}
	}

	return "", &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "either credential_configuration_id or credential_identifier must be provided"}
}
