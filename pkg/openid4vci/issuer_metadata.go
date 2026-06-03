package openid4vci

import (
	"context"
	"encoding/json"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// CredentialIssuerMetadataParameters https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
type CredentialIssuerMetadataParameters struct {
	// CredentialIssuer: REQUIRED. The Credential Issuer's identifier, as defined in Section 12.2.1.
	CredentialIssuer string `json:"credential_issuer" yaml:"credential_issuer" validate:"required"`

	// AuthorizationServers: OPTIONAL. A non-empty array of strings, where each string is an identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization.
	AuthorizationServers []string `json:"authorization_servers,omitempty" yaml:"authorization_servers,omitempty"`

	// CredentialEndpoint: REQUIRED. URL of the Credential Issuer's Credential Endpoint, as defined in Section 8.2. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	CredentialEndpoint string `json:"credential_endpoint" yaml:"credential_endpoint" validate:"required"`

	// NonceEndpoint: OPTIONAL. URL of the Credential Issuer's Nonce Endpoint, as defined in Section 7. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not require the use of c_nonce.
	NonceEndpoint string `json:"nonce_endpoint,omitempty" yaml:"nonce_endpoint,omitempty"`

	// DeferredCredentialEndpoint: OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
	DeferredCredentialEndpoint string `json:"deferred_credential_endpoint,omitempty" yaml:"deferred_credential_endpoint,omitempty"`

	// NotificationEndpoint: OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 11. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
	NotificationEndpoint string `json:"notification_endpoint,omitempty" yaml:"notification_endpoint,omitempty"`

	// CredentialResponseEncryption: OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential Response on top of TLS.
	CredentialResponseEncryption *MetadataCredentialResponseEncryption `json:"credential_response_encryption,omitempty" yaml:"credential_response_encryption" validate:"omitempty"`

	// BatchCredentialIssuance: OPTIONAL. Object containing information about the Credential Issuer's support for batch issuance of Credentials on the Credential Endpoint.
	BatchCredentialIssuance *BatchCredentialIssuance `json:"batch_credential_issuance,omitempty" yaml:"batch_credential_issuance,omitempty"`

	// Display: OPTIONAL. A non-empty array of objects, where each object contains display properties of a Credential Issuer for a certain language.
	Display []MetadataDisplay `json:"display,omitempty" yaml:"display,omitempty"`

	// SignedMetadata: OPTIONAL. A JWT that contains Credential Issuer metadata parameters as claims.
	SignedMetadata string `json:"signed_metadata,omitempty" yaml:"signed_metadata,omitempty"`

	// CredentialConfigurationsSupported: REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of. This object contains a list of name/value pairs, where each name is a unique identifier of the supported Credential being described.
	CredentialConfigurationsSupported map[string]CredentialConfigurationsSupported `json:"credential_configurations_supported" yaml:"credential_configurations_supported" validate:"required"`
}

// MetadataIssuer returns the issuer identifier embedded in the metadata
// (credential_issuer), used to verify it matches the request's iss claim.
func (c *CredentialIssuerMetadataParameters) MetadataIssuer() string {
	return c.CredentialIssuer
}

func (c *CredentialIssuerMetadataParameters) MarshalJWTClaims() (jwt.MapClaims, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Sign creates a signed JWT representation of the metadata and sets the signed_metadata field.
// Per OID4VCI 1.0 Section 12.2.4, signed_metadata is an OPTIONAL JWT that contains the
// Credential Issuer metadata parameters as claims, using typ "openidvci-issuer-metadata+jwt".
func (c *CredentialIssuerMetadataParameters) Sign(ctx context.Context, signer pki.Signer, x5c []string) (*CredentialIssuerMetadataParameters, error) {
	header := jwt.MapClaims{
		"typ": "openidvci-issuer-metadata+jwt",
		"x5c": x5c,
	}

	body, err := c.MarshalJWTClaims()
	if err != nil {
		return nil, err
	}

	body["iat"] = time.Now().Unix()
	body["iss"] = c.CredentialIssuer
	body["sub"] = c.CredentialIssuer

	// Remove signed_metadata from the JWT payload to avoid self-referencing
	delete(body, "signed_metadata")

	reply, err := jose.MakeJWT(ctx, header, body, signer)
	if err != nil {
		return nil, err
	}

	c.SignedMetadata = reply

	return c, nil
}

// MetadataCredentialResponseEncryption Object containing information about whether the Credential Issuer supports encryption of the Credential and Batch Credential Response on top of TLS.
type MetadataCredentialResponseEncryption struct {
	// AlgValuesSupported: REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
	AlgValuesSupported []string `json:"alg_values_supported" yaml:"alg_values_supported" validate:"required"`

	// EncValuesSupported: REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
	EncValuesSupported []string `json:"enc_values_supported" yaml:"enc_values_supported" validate:"required"`

	// EncryptionRequired: REQUIRED. Boolean value specifying whether the Credential Issuer requires the additional encryption on top of TLS for the Credential Response. If the value is true, the Credential Issuer requires encryption for every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request. If the value is false, the Wallet MAY chose whether it provides encryption keys or not.
	EncryptionRequired bool `json:"encryption_required" yaml:"encryption_required"`
}

type BatchCredentialIssuance struct {
	// BatchSize: REQUIRED. Integer value specifying the maximum array size for the proofs parameter in a Credential Request.
	BatchSize int `json:"batch_size" yaml:"batch_size" validate:"required"`
}

// MetadataDisplay contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
type MetadataDisplay struct {
	// Name: OPTIONAL. String value of a display name for the Credential Issuer.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Locale: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. There MUST be only one object for each language identifier.
	Locale string `json:"locale,omitempty" yaml:"locale,omitempty" validate:"bcp47_language_tag"`

	// Logo: OPTIONAL. Object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:
	Logo *MetadataLogo `json:"logo,omitempty" yaml:"logo,omitempty"`
}

// MetadataLogo object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:
type MetadataLogo struct {
	// URI: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.
	URI string `json:"uri" yaml:"uri" validate:"required"`

	// AltText: OPTIONAL. String value of the alternative text for the logo image.
	AltText string `json:"alt_text,omitempty" yaml:"alt_text,omitempty"`
}

// CredentialConfigurationsSupported Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
type CredentialConfigurationsSupported struct {
	// Format: REQUIRED. A JSON string identifying the format of this Credential, e.g., dc+sd-jwt, mso_mdoc, jwt_vc_json, ldp_vc.
	Format string `json:"format" yaml:"format" validate:"required"`

	// Scope: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential.
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`

	// CredentialSigningAlgValuesSupported: OPTIONAL. A non-empty array of algorithm identifiers that the Issuer uses to sign the issued Credential.
	// For dc+sd-jwt format, these are strings like "ES256". For mso_mdoc format, these are COSE algorithm identifiers (integers like -7 for ES256).
	CredentialSigningAlgValuesSupported []any `json:"credential_signing_alg_values_supported,omitempty" yaml:"credential_signing_alg_values_supported,omitempty"`

	// CryptographicBindingMethodsSupported: OPTIONAL. A non-empty array of case sensitive strings that identify the representation of the cryptographic key material that the issued Credential is bound to.
	// Valid values include "jwk", "cose_key", and DID method prefixes like "did:key", "did:web", "did:jwk", etc.
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty" yaml:"cryptographic_binding_methods_supported,omitempty"`

	// ProofTypesSupported: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports.
	ProofTypesSupported map[string]ProofsTypesSupported `json:"proof_types_supported,omitempty" yaml:"proof_types_supported,omitempty"`

	// CredentialMetadata: OPTIONAL. Object containing information relevant to the usage and display of issued Credentials.
	CredentialMetadata *CredentialMetadata `json:"credential_metadata,omitempty" yaml:"credential_metadata,omitempty"`

	// --- Format-specific parameters (Appendix A) ---

	// VCT: REQUIRED for dc+sd-jwt format. String designating the type of the Credential, as defined in SD-JWT VC.
	VCT string `json:"vct,omitempty" yaml:"vct,omitempty"`

	// CredentialDefinition: REQUIRED for jwt_vc_json and ldp_vc formats. Object containing the detailed description of the Credential type.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty" yaml:"credential_definition,omitempty"`

	// Doctype: REQUIRED for mso_mdoc format. String identifying the Credential type, as defined in ISO 18013-5.
	Doctype string `json:"doctype,omitempty" yaml:"doctype,omitempty"`

	// Cryptosuite: OPTIONAL. For ldp_vc and vc+ld+json formats, identifies the cryptographic suite used for Data Integrity Proofs.
	Cryptosuite string `json:"cryptosuite,omitempty" yaml:"cryptosuite,omitempty"`
}

// ProofsTypesSupported Object that describes specifics of the key proof(s) that the Credential Issuer supports.
type ProofsTypesSupported struct {
	// ProofSigningAlgValuesSupported: REQUIRED. Array of case sensitive strings that identify the algorithms that the Issuer supports for this proof type. The Wallet uses one of them to sign the proof. Algorithm names used are determined by the key proof type and are defined in Section 7.2.1.
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported" yaml:"proof_signing_alg_values_supported" validate:"required"`
}

// CredentialMetadata contains information relevant to the usage and display of issued Credentials.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
type CredentialMetadata struct {
	// Display: OPTIONAL. A non-empty array of objects, where each object contains the display properties of the supported Credential for a certain language.
	Display []CredentialMetadataDisplay `json:"display,omitempty" yaml:"display,omitempty"`

	// Claims: OPTIONAL. A non-empty array of claims description objects as defined in Appendix B.2.
	Claims []ClaimDescription `json:"claims,omitempty" yaml:"claims,omitempty"`
}

// ClaimDescription describes a claim within a Credential for display purposes.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-claims-description-for-issu
type ClaimDescription struct {
	// Path: REQUIRED. A non-empty array representing a claims path pointer that specifies the path to a claim within the credential.
	Path []string `json:"path" yaml:"path" validate:"required"`

	// Mandatory: OPTIONAL. Boolean which, when set to true, indicates that the Credential Issuer will always include this claim.
	Mandatory bool `json:"mandatory,omitempty" yaml:"mandatory,omitempty"`

	// Display: OPTIONAL. A non-empty array of objects containing display properties for the claim.
	Display []ClaimDisplayProperties `json:"display,omitempty" yaml:"display,omitempty"`
}

// ClaimDisplayProperties contains display properties for a claim.
type ClaimDisplayProperties struct {
	// Name: OPTIONAL. String value of a display name for the claim.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Locale: OPTIONAL. String value that identifies the language of this object.
	Locale string `json:"locale,omitempty" yaml:"locale,omitempty" validate:"bcp47_language_tag"`
}

// CredentialDefinition describes the Credential type for W3C VC formats (jwt_vc_json, ldp_vc).
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.2
type CredentialDefinition struct {
	// Type: REQUIRED. Array designating the types a certain Credential type supports, according to [VC_DATA], Section 4.3.
	Type []string `json:"type" yaml:"type" validate:"required"`

	// Context: REQUIRED for ldp_vc. Array as defined in [VC_DATA], Section 4.1.
	// Note: conditionally required — must be enforced at the application level based on format.
	Context []string `json:"@context,omitempty" yaml:"@context,omitempty"`
}

// CredentialMetadataDisplay displays properties of the supported Credential for a certain language.
type CredentialMetadataDisplay struct {
	// Name: REQUIRED. String value of a display name for the Credential.
	Name string `json:"name" yaml:"name" validate:"required"`

	// Locale: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object for each language identifier.
	Locale string `json:"locale,omitempty" yaml:"locale,omitempty" validate:"bcp47_language_tag"`

	// Logo: OPTIONAL. Object with information about the logo of the Credential
	Logo *MetadataLogo `json:"logo,omitempty" yaml:"logo,omitempty"`

	// Description: OPTIONAL. String value of a description of the Credential.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// BackgroundColor: OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
	BackgroundColor string `json:"background_color,omitempty" yaml:"background_color,omitempty"`

	// BackgroundImage: OPTIONAL. Object with information about the background image of the Credential. At least the following parameter MUST be included:
	BackgroundImage *MetadataBackgroundImage `json:"background_image,omitempty" yaml:"background_image,omitempty"`

	// TextColor: OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
	TextColor string `json:"text_color,omitempty" yaml:"text_color,omitempty"`
}

// MetadataBackgroundImage contains  information about the background image of the Credential
type MetadataBackgroundImage struct {
	// URI REQUIRED. String value that contains a URI where the Wallet can obtain the background image of the Credential from the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.
	URI string `json:"uri" yaml:"uri" validate:"required"`
}
