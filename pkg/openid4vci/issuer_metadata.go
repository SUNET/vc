package openid4vci

import (
	"context"
	"encoding/json"
	"time"
	"vc/pkg/jose"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// CredentialIssuerMetadataParameters https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-p
type CredentialIssuerMetadataParameters struct {
	// CredentialIssuer: REQUIRED. The Credential Issuer's identifier, as defined in Section 11.2.1.
	CredentialIssuer string `json:"credential_issuer" yaml:"credential_issuer" validate:"required"`

	//AuthorizationServers: OPTIONAL. Array of strings, where each string is an identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server, i.e., the Credential Issuer's identifier is used to obtain the Authorization Server metadata. The actual OAuth 2.0 Authorization Server metadata is obtained from the oauth-authorization-server well-known location as defined in Section 3 of [RFC8414]. When there are multiple entries in the array, the Wallet may be able to determine which Authorization Server to use by querying the metadata; for example, by examining the grant_types_supported values, the Wallet can filter the server to use based on the grant type it plans to use. When the Wallet is using authorization_server parameter in the Credential Offer as a hint to determine which Authorization Server to use out of multiple, the Wallet MUST NOT proceed with the flow if the authorization_server Credential Offer parameter value does not match any of the entries in the authorization_servers array.
	AuthorizationServers []string `json:"authorization_servers,omitempty" yaml:"authorization_servers,omitempty"`

	//CredentialEndpoint  REQUIRED. URL of the Credential Issuer's Credential Endpoint, as defined in Section 7.2. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	CredentialEndpoint string `json:"credential_endpoint" yaml:"credential_endpoint" validate:"required"`

	// DeferredCredentialEndpoint: OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
	DeferredCredentialEndpoint string `json:"deferred_credential_endpoint,omitempty" yaml:"deferred_credential_endpoint,omitempty"`

	// NotificationEndpoint: OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 10. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
	NotificationEndpoint string `json:"notification_endpoint,omitempty" yaml:"notification_endpoint,omitempty"`

	// CredentialResponseEncryption: OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential and Batch Credential Response on top of TLS
	CredentialResponseEncryption *MetadataCredentialResponseEncryption `json:"credential_response_encryption,omitempty" yaml:"credential_response_encryption" validate:"omitempty"`

	// BatchCredentialIssuance OPTIONAL. Object containing information about the Credential Issuer's supports for batch issuance of Credentials on the Credential Endpoint. The presence of this parameter means that the issuer supports the proofs parameter in the Credential Request so can issue more than one Verifiable Credential for the same Credential Dataset in a single request/response.
	BatchCredentialIssuance *BatchCredentialIssuance `json:"batch_credential_issuance,omitempty" yaml:"batch_credential_issuance,omitempty"`

	//SignedMetadata: OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims. The signed metadata MUST be secured using JSON Web Signature (JWS) [RFC7515] and MUST contain an iat (Issued At) claim, an iss (Issuer) claim denoting the party attesting to the claims in the signed metadata, and sub (Subject) claim matching the Credential Issuer identifier. If the Wallet supports signed metadata, metadata values conveyed in the signed JWT MUST take precedence over the corresponding values conveyed using plain JSON elements. If the Credential Issuer wants to enforce use of signed metadata, it omits the respective metadata parameters from the unsigned part of the Credential Issuer metadata. A signed_metadata metadata value MUST NOT appear as a claim in the JWT. The Wallet MUST establish trust in the signer of the metadata, and obtain the keys to validate the signature before processing the metadata. The concrete mechanism how to do that is out of scope of this specification and MAY be defined in the profiles of this specification.
	SignedMetadata string `json:"signed_metadata,omitempty" yaml:"signed_metadata,omitempty"`

	// Display: OPTIONAL. Array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
	Display []MetadataDisplay `json:"display,omitempty" yaml:"display,omitempty"`

	// CredentialConfigurationsSupported: REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of. This object contains a list of name/value pairs, where each name is a unique identifier of the supported Credential being described. This identifier is used in the Credential Offer as defined in Section 4.1.1 to communicate to the Wallet which Credential is being offered. The value is an object that contains metadata about a specific Credential and contains the following parameters defined by this specification
	CredentialConfigurationsSupported map[string]CredentialConfigurationsSupported `json:"credential_configurations_supported" yaml:"credential_configurations_supported" validate:"required"`
}

func (c *CredentialIssuerMetadataParameters) Marshal() (jwt.MapClaims, error) {
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

// Sign creates a signed JWT of the metadata using pki.Signer.
// The pki.Signer interface supports both software keys and HSM.
func (c *CredentialIssuerMetadataParameters) Sign(ctx context.Context, signer pki.Signer, x5c []string) (*CredentialIssuerMetadataParameters, error) {
	header := jwt.MapClaims{
		"typ": "JWT",
		"x5c": x5c,
	}

	// ensure that signed_metadata is empty
	c.SignedMetadata = ""

	body, err := c.Marshal()
	if err != nil {
		return nil, err
	}

	body["iat"] = time.Now().Unix()
	body["iss"] = c.CredentialIssuer
	body["sub"] = c.CredentialIssuer

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
	//BatchSize: REQUIRED. Integer value specifying the maximum array size for the proofs parameter in a Credential Request.
	BatchSize int `json:"batch_size" yaml:"batch_size" validate:"required"`
}

// MetadataDisplay contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
type MetadataDisplay struct {
	// Name: OPTIONAL. String value of a display name for the Credential Issuer.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	//Locale: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. There MUST be only one object for each language identifier.
	Locale string `json:"locale,omitempty" yaml:"locale,omitempty" validate:"bcp47_language_tag"`

	// Logo: OPTIONAL. Object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:
	Logo MetadataLogo `json:"logo,omitempty" yaml:"logo,omitempty"`
}

// MetadataLogo object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:
type MetadataLogo struct {
	//URI: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.
	URI string `json:"uri" yaml:"uri" validate:"required"`

	// AltText: OPTIONAL. String value of the alternative text for the logo image.
	AltText string `json:"alt_text,omitempty" yaml:"alt_text,omitempty"`
}

// CredentialConfigurationsSupported Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
type CredentialConfigurationsSupported struct {
	// Format: REQUIRED. A JSON string identifying the format of this Credential, i.e., jwt_vc_json or ldp_vc. Depending on the format value, the object contains further elements defining the type and (optionally) particular claims the Credential MAY contain and information about how to display the Credential. Appendix A contains Credential Format Profiles introduced by this specification.
	Format string `json:"format" yaml:"format" validate:"required"`

	// Doctype MDOC specific parameter
	Doctype string `json:"doctype,omitempty" yaml:"doctype,omitempty"`

	// Cryptosuite: OPTIONAL. For ldp_vc and vc+ld+json formats, identifies the cryptographic suite used for
	// Data Integrity Proofs. Valid values include: ecdsa-rdfc-2019, ecdsa-sd-2023, eddsa-rdfc-2022.
	Cryptosuite string `json:"cryptosuite,omitempty" yaml:"cryptosuite,omitempty"`

	// Scope: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential. The value can be the same across multiple credential_configurations_supported objects. The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the scope value. The Wallet can use this value in the Authorization Request as defined in Section 5.1.2. Scope values in this Credential Issuer metadata MAY duplicate those in the scopes_supported parameter of the Authorization Server.
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`

	// CryptographicBindingMethodsSupported: OPTIONAL. Array of case sensitive strings that identify the representation of the cryptographic key material that the issued Credential is bound to, as defined in Section 7.1. Support for keys in JWK format [RFC7517] is indicated by the value jwk. Support for keys expressed as a COSE Key object [RFC8152] (for example, used in [ISO.18013-5]) is indicated by the value cose_key. When the Cryptographic Binding Method is a DID, valid values are a did: prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without a :and method-specific-id. For example, support for the DID method with a method-name "example" would be represented by did:example.
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty" yaml:"cryptographic_binding_methods_supported,omitempty" validate:"omitempty,dive,oneof=jwk cose_key did:example"`

	// CredentialSigningAlgValuesSupported: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
	// For dc+sd-jwt format, these are strings like "ES256". For mso_mdoc format, these are COSE algorithm identifiers (integers like -7 for ES256).
	CredentialSigningAlgValuesSupported []any `json:"credential_signing_alg_values_supported,omitempty" yaml:"credential_signing_alg_values_supported,omitempty"`

	// ProofTypesSupported: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports. This object contains a list of name/value pairs, where each name is a unique identifier of the supported proof type(s). Valid values are defined in Section 7.2.1, other values MAY be used. This identifier is also used by the Wallet in the Credential Request as defined in Section 7.2. The value in the name/value pair is an object that contains metadata about the key proof and contains the following parameters defined by this specification:
	ProofTypesSupported map[string]ProofsTypesSupported `json:"proof_types_supported" yaml:"proof_types_supported"`

	// Display: OPTIONAL. Array of objects, where each object contains the display properties of the supported Credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included.
	Display []CredentialMetadataDisplay `json:"display,omitempty" yaml:"display,omitempty"`

	// CredentialDefinition REQUIRED. Object containing the detailed description of the Credential type. It consists of at least the following two parameters
	CredentialDefinition CredentialDefinition `json:"credential_definition" yaml:"credential_definition" validate:"required"`
	VCT                  string               `json:"vct,omitempty" yaml:"vct,omitempty"`
}

// ProofsTypesSupported Object that describes specifics of the key proof(s) that the Credential Issuer supports.
type ProofsTypesSupported struct {
	//ProofSigningAlgValuesSupported: REQUIRED. Array of case sensitive strings that identify the algorithms that the Issuer supports for this proof type. The Wallet uses one of them to sign the proof. Algorithm names used are determined by the key proof type and are defined in Section 7.2.1.
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported" yaml:"proof_signing_alg_values_supported" validate:"required"`
}

type CredentialSubject struct {
	//Mandatory: OPTIONAL. Boolean which, when set to true, indicates that the Credential Issuer will always include this claim in the issued Credential. If set to false, the claim is not included in the issued Credential if the wallet did not request the inclusion of the claim, and/or if the Credential Issuer chose to not include the claim. If the mandatory parameter is omitted, the default value is false.
	Mandatory bool `json:"mandatory,omitempty" yaml:"mandatory,omitempty"`

	//ValueType: OPTIONAL. String value determining the type of value of the claim. Valid values defined by this specification are string, number, and image media types such as image/jpeg as defined in IANA media type registry for images (https://www.iana.org/assignments/media-types/media-types.xhtml#image). Other values MAY also be used.
	ValueType string `json:"value_type,omitempty" yaml:"value_type,omitempty"`

	Display []CredentialMetadataDisplay `json:"display,omitempty" yaml:"display,omitempty"`
}

type CredentialDefinition struct {
	// Type REQUIRED. Array designating the types a certain Credential type supports, according to [VC_DATA], Section 4.3.
	Type []string `json:"type" yaml:"type" validate:"required"`
}

// CredentialMetadataDisplay displays properties of the supported Credential for a certain language.
type CredentialMetadataDisplay struct {
	// Name: REQUIRED. String value of a display name for the Credential.
	Name string `json:"name" yaml:"name" validate:"required"`

	// Locale: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object for each language identifier.
	Locale string `json:"locale,omitempty" yaml:"locale,omitempty" validate:"bcp47_language_tag"`

	// Logo: OPTIONAL. Object with information about the logo of the Credential
	Logo MetadataLogo `json:"logo,omitempty" yaml:"logo,omitempty"`

	// Description: OPTIONAL. String value of a description of the Credential.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// BackgroundColor: OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
	BackgroundColor string `json:"background_color,omitempty" yaml:"background_color,omitempty"`

	// BackgroundImage: OPTIONAL. Object with information about the background image of the Credential. At least the following parameter MUST be included:
	BackgroundImage MetadataBackgroundImage `json:"background_image,omitempty" yaml:"background_image,omitempty"`

	// TextColor: OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
	TextColor string `json:"text_color,omitempty" yaml:"text_color,omitempty"`
}

// MetadataBackgroundImage contains  information about the background image of the Credential
type MetadataBackgroundImage struct {
	// URI REQUIRED. String value that contains a URI where the Wallet can obtain the background image of the Credential from the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.
	URI string `json:"uri" yaml:"uri" validate:"required"`
}
