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
	fmt.Println("Token: ", token)

	tokenS256 := sha256.Sum256([]byte(token))
	fmt.Printf("Token SHA256: %x\n", tokenS256)

	b64 := base64.RawURLEncoding.EncodeToString(tokenS256[:])
	fmt.Println("Base64 Raw Encoded Token SHA256: ", b64)
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

	if hasAuthDetails {
		// authorization_details flow: credential_identifier is REQUIRED
		if c.CredentialIdentifier == "" {
			return fmt.Errorf("credential_identifier is required when authorization_details was returned in the Token Response")
		}
		if c.CredentialConfigurationID != "" {
			return fmt.Errorf("credential_configuration_id must not be present when credential_identifier is used")
		}

		// Verify credential_identifier matches one returned in the Token Response
		for _, ad := range authorizationDetails {
			if slices.Contains(ad.CredentialIdentifiers, c.CredentialIdentifier) {
				return nil
			}
		}
		return fmt.Errorf("credential_identifier %q not found in Token Response authorization_details", c.CredentialIdentifier)
	}

	// scope-based flow: credential_configuration_id is REQUIRED
	if c.CredentialConfigurationID == "" {
		return fmt.Errorf("credential_configuration_id is required when authorization_details was not returned in the Token Response")
	}
	if c.CredentialIdentifier != "" {
		return fmt.Errorf("credential_identifier must not be present when credential_configuration_id is used")
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

	//NotificationID: OPTIONAL. String identifying an issued Credential that the Wallet includes in the Notification Request as defined in Section 10.1. This parameter MUST NOT be present if credential parameter is not present.
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

// ExtractAllJWKs extracts one JWK per proof for batch credential issuance.
// For JWT and DIVP proof types, each proof in the array yields one JWK.
// For Attestation, all keys from the attested_keys claim are returned.
func (p *Proofs) ExtractAllJWKs() ([]*apiv1_issuer.Jwk, error) {
	if len(p.JWT) > 0 {
		jwks := make([]*apiv1_issuer.Jwk, 0, len(p.JWT))
		for i, token := range p.JWT {
			jwk, err := token.ExtractJWK()
			if err != nil {
				return nil, fmt.Errorf("failed to extract JWK from JWT proof %d: %w", i, err)
			}
			jwks = append(jwks, jwk)
		}
		return jwks, nil
	}

	if len(p.DIVP) > 0 {
		jwks := make([]*apiv1_issuer.Jwk, 0, len(p.DIVP))
		for i, vp := range p.DIVP {
			jwk, err := vp.ExtractJWK()
			if err != nil {
				return nil, fmt.Errorf("failed to extract JWK from DIVP proof %d: %w", i, err)
			}
			jwks = append(jwks, jwk)
		}
		return jwks, nil
	}

	if p.Attestation != "" {
		return p.Attestation.ExtractAllJWKs()
	}

	return nil, fmt.Errorf("no proofs found")
}

// Count returns the number of proofs present in the batch.
// Only one proof type should be populated per request.
//
// DEPRECATED: Since getting the correct count for Attestation proofs
// requires extracting the JWKs, it makes more sense to use `len(ExtractAllJWKs())`
// to get the count of proofs for batch processing, making this redundant and currently
// only accurate for JWT and DIVP proof types.
func (p *Proofs) Count() int {
	if len(p.JWT) > 0 {
		return len(p.JWT)
	}
	if len(p.DIVP) > 0 {
		return len(p.DIVP)
	}
	if p.Attestation != "" {
		// Attestation has one JWT but may attest multiple keys
		return 1
	}
	return 0
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
func (req *CredentialRequest) ResolveCredentialFormat(metadata *CredentialIssuerMetadataParameters) (string, error) {
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
		return "", fmt.Errorf("unknown credential_configuration_id: %s", req.CredentialConfigurationID)
	}

	// Use credential_identifier to look up the format
	// The credential_identifier maps to a credential configuration via authorization_details from the token response
	// For now, we'll attempt to find a matching configuration by identifier
	if req.CredentialIdentifier != "" {
		if metadata.CredentialConfigurationsSupported != nil {
			// Try to match by credential identifier (may be same as configuration ID in some cases)
			if config, ok := metadata.CredentialConfigurationsSupported[req.CredentialIdentifier]; ok {
				return config.Format, nil
			}
			// If not found directly, we need the authorization context to resolve credential_identifier
			// For now, default to dc+sd-jwt as a fallback
			return "dc+sd-jwt", nil
		}
		return "", fmt.Errorf("unknown credential_identifier: %s", req.CredentialIdentifier)
	}

	return "", fmt.Errorf("either credential_configuration_id or credential_identifier must be provided")
}
