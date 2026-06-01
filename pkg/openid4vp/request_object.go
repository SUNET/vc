package openid4vp

import (
	"encoding/base64"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RequestObject is sent by authorization request
type RequestObject struct {
	// ISS MAY be present in the Request Object. However, if it is present, the Wallet MUST ignore it.
	ISS string `json:"iss" uri:"iss" validate:"required,url"`

	AUD string `json:"aud,omitempty" bson:"aud,omitempty" validate:"required"`

	IAT int64 `json:"iat,omitempty" bson:"iat,omitempty" validate:"required"`

	// ResponseType        REQUIRED.  Value MUST be set to "code".
	ResponseType string `json:"response_type" uri:"response_type" validate:"required,eq=code"`

	// REQUIRED. Defined in [RFC6749]. This specification defines additional requirements to enable the use of Client Identifier Prefixes as described in Section 5.9. The Client Identifier can be created by parties other than the Wallet and it is considered unique within the context of the Wallet when used in combination with the Client Identifier Prefix.
	ClientID string `json:"client_id" uri:"client_id" validate:"required"`

	// RedirectURI OPTIONAL.  As described in Section 3.1.2.
	RedirectURI string `json:"redirect_uri,omitempty" uri:"redirect_uri" validate:"omitempty,url"`

	// Scope OPTIONAL.  The scope of the access request as described by Section 3.3.
	Scope string `json:"scope,omitempty" uri:"scope" validate:"omitempty"`

	//  State REQUIRED under the conditions defined in Section 5.3. Otherwise, state is OPTIONAL. state values MUST only contain ASCII URL safe characters (uppercase and lowercase letters, decimal digits, hyphen, period, underscore, and tilde).
	State string `json:"state,omitempty" uri:"state" validate:"omitempty"`

	// Nonce REQUIRED. A case-sensitive String representing a value to securely bind Verifiable Presentation(s) provided by the Wallet to the particular transaction. The Verifier MUST create a fresh, cryptographically random number with sufficient entropy for every Authorization Request, store it with its current session, and pass it in the nonce Authorization Request Parameter to the Wallet. See Section 14.1 for details. Values MUST only contain ASCII URL safe characters (uppercase and lowercase letters, decimal digits, hyphen, period, underscore, and tilde).
	Nonce string `json:"nonce" uri:"nonce" validate:"required"`

	// ResponseMode REQUIRED. Defined in [OAuth.Responses]. This parameter can be used (through the new Response Mode direct_post) to ask the Wallet to send the response to the Verifier via an HTTPS connection (see Section 8.2 for more details). It can also be used to request that the resulting response be encrypted (see Section 8.3 for more details).
	ResponseMode string `json:"response_mode,omitempty" uri:"response_mode" validate:"omitempty,oneof=form_post direct_post direct_post.jwt dc_api.jwt"`

	// dcql_query
	DCQLQuery *DCQL `json:"dcql_query,omitempty" bson:"dcql_query,omitempty" validate:"omitempty,dive"`

	// PresentationDefinition *PresentationDefinitionParameter `json:"presentation_definition,omitempty" bson:"presentation_definition,omitempty" validate:"omitempty,dive"`

	// ClientMetadata OPTIONAL. A JSON object containing the Verifier metadata values. It MUST be UTF-8 encoded.
	ClientMetadata *ClientMetadata `json:"client_metadata,omitempty" validate:"omitempty"`

	// RequestURIMethod: OPTIONAL. A string determining the HTTP method to be used when the request_uri parameter is included in the same request. Two case-sensitive valid values are defined in this specification: get and post. If request_uri_method value is get, the Wallet MUST send the request to retrieve the Request Object using the HTTP GET method, i.e., as defined in [RFC9101]. If request_uri_method value is post, a supporting Wallet MUST send the request using the HTTP POST method as detailed in Section 5.10. If the request_uri_method parameter is not present, the Wallet MUST process the request_uri parameter as defined in [RFC9101]. Wallets not supporting the post method will send a GET request to the Request URI (default behavior as defined in [RFC9101]). request_uri_method parameter MUST NOT be present if a request_uri parameter is not present. If the Verifier set the request_uri_method parameter value to post and there is no other means to convey its capabilities to the Wallet, it SHOULD add the client_metadata parameter to the Authorization Request. This enables the Wallet to assess the Verifier's capabilities, allowing it to transmit only the relevant capabilities through the wallet_metadata parameter in the Request URI POST request.
	RequestURIMethod string `json:"request_uri_method,omitempty" bson:"request_uri_method,omitempty" validate:"omitempty,oneof=get post"`

	// TransactionData OPTIONAL. Non-empty array of strings, where each string is a base64url-encoded JSON object that contains a typed parameter set with details about the transaction that the Verifier is requesting the End-User to authorize. See Section 8.4 for details. The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction data not conforming to the respective type definition
	TransactionData []TransactionData `json:"transaction_data,omitempty" bson:"transaction_data,omitempty" validate:"omitempty,dive,required"`

	// VerifierInfo OPTIONAL. A non-empty array of attestations about the Verifier relevant to the Credential Request. These attestations MAY include Verifier metadata, policies, trust status, or authorizations. Attestations are intended to support authorization decisions, inform Wallet policy enforcement, or enrich the End-User consent dialog.
	VerifierInfo []VerifierInfo `json:"verifier_info,omitempty" bson:"verifier_info,omitempty" validate:"omitempty,dive,required"`

	// ResponseURI REQUIRED when the Response Mode direct_post is used. The URL to which the Wallet MUST send the Authorization Response using an HTTP POST request as defined by the Response Mode direct_post. The Response URI receives all Authorization Response parameters as defined by the respective Response Type. When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error. The response_uri value MUST be a value that the client would be permitted to use as redirect_uri when following the rules defined in Section 5.9.
	ResponseURI string `json:"response_uri,omitempty" uri:"response_uri" validate:"required"`
}

type VerifierInfo struct {
	//	Format: REQUIRED. A string that identifies the format of the attestation and how it is encoded. Ecosystems SHOULD use collision-resistant identifiers. Further processing of the attestation is determined by the type of the attestation, which is specified in a format-specific way.
	Format string `json:"format" bson:"format" validate:"required"`

	// Data: REQUIRED. An object or string containing an attestation (e.g. a JWT). The payload structure is defined on a per format level. It is at the discretion of the Wallet whether it uses the information from verifier_info. Factors that influence such Wallet's decision include, but are not limited to, trust framework the Wallet supports, specific policies defined by the Issuers or ecosystem, and profiles of this specification. If the Wallet uses information from verifier_info, the Wallet MUST validate the signature and ensure binding.
	Data string `json:"data" bson:"data" validate:"required"`

	// credential_ids: OPTIONAL. A non-empty array of strings each referencing a Credential requested by the Verifier for which the attestation is relevant. Each string matches the id field in a DCQL Credential Query. If omitted, the attestation is relevant to all requested Credentials.
	CredentialIDS []string `json:"credential_ids,omitempty" bson:"credential_ids,omitempty" validate:"omitempty,dive,required"`
}

type ClientMetadata struct {
	// JWKS OPTIONAL. A JSON Web Key Set, as defined in [RFC7591], that contains one or more public keys, such as those used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response (see Section 8.3), or where the Wallet will require the public key of the Verifier to generate a Verifiable Presentation. This allows the Verifier to pass ephemeral keys specific to this Authorization Request. Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests. Each JWK in the set MUST have a kid (Key ID) parameter that uniquely identifies the key within the context of the request.
	JWKS *Keys `json:"jwks,omitempty" bson:"jwks,omitempty" validate:"omitempty"`

	// encrypted_response_enc_values_supported: OPTIONAL. Non-empty array of strings, where each string is a JWE [RFC7516] enc algorithm that can be used as the content encryption algorithm for encrypting the Response. When a response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) is specified, this MUST be present for anything other than the default single value of A128GCM. Otherwise, this SHOULD be absent.
	EncryptedResponseEncValuesSupported []string `json:"encrypted_response_enc_values_supported,omitempty" bson:"encrypted_response_enc_values_supported,omitempty" validate:"omitempty,dive,oneof=A128CBC-HS256 A256CBC-HS512 A128GCM A256GCM"`

	// vp_formats_supported: REQUIRED when not available to the Wallet via another mechanism. As defined in Section 11.1.
	// Per OpenID4VP spec, this is the properly formatted field for client_metadata in authorization requests
	VPFormatsSupported *VPFormatsSupported `json:"vp_formats_supported,omitempty" bson:"vp_formats_supported,omitempty"`

	// authorization_signed_response_alg: OPTIONAL. As defined in [JARM].
	AuthorizationSignedResponseALG string `json:"authorization_signed_response_alg,omitempty" bson:"authorization_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 PS256 EdDSA"`
	// authorization_encrypted_response_alg: OPTIONAL. As defined in [JARM].
	AuthorizationEncryptedResponseALG string `json:"authorization_encrypted_response_alg,omitempty" bson:"authorization_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES A128GCMKW A256GCMKW"`
	// authorization_encrypted_response_enc: OPTIONAL. As defined in [JARM].
	AuthorizationEncryptedResponseENC string `json:"authorization_encrypted_response_enc,omitempty" bson:"authorization_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A256CBC-HS512 A128GCM A256GCM"`
}

type Keys struct {
	Keys []jwk.Key `json:"keys,omitempty" bson:"keys,omitempty" validate:"omitempty,dive"`
}

type JWK struct {
	KTY string `json:"kty,omitempty" bson:"kty,omitempty" validate:"required,oneof=RSA EC OKP"`
	X   string `json:"x,omitempty" bson:"x,omitempty" validate:"omitempty"`
	Y   string `json:"y,omitempty" bson:"y,omitempty" validate:"omitempty"`
	CRV string `json:"crv,omitempty" bson:"crv,omitempty" validate:"omitempty,oneof=P-256 P-384 P-521 Ed25519 Ed448 X25519 X448"`
	N   string `json:"n,omitempty" bson:"n,omitempty" validate:"omitempty"`
	KID string `json:"kid,omitempty" bson:"kid,omitempty" validate:"omitempty"`
	E   string `json:"e,omitempty" bson:"e,omitempty" validate:"omitempty"`
	Use string `json:"use,omitempty" bson:"use,omitempty" validate:"omitempty,oneof=sig enc"`
	Alg string `json:"alg,omitempty" bson:"alg,omitempty"`
}

type TransactionData struct {
	// Type REQUIRED. String that identifies the type of transaction data. This value determines parameters that can be included in the transaction_data object. The specific values are out of scope for this specification. It is RECOMMENDED to use collision-resistant names for type values.
	Type string `json:"type,omitempty" bson:"type,omitempty" validate:"required"`

	// CredentialIDS REQUIRED. Non-empty array of strings each referencing a Credential requested by the Verifier that can be used to authorize this transaction. The string matches the id field in the DCQL Credential Query. If there is more than one element in the array, the Wallet MUST use only one of the referenced Credentials for transaction authorization.
	CredentialIDS []string `json:"credential_ids,omitempty" bson:"credential_ids,omitempty" validate:"required,dive,required"`
}

// Base64Encode encodes the TransactionData struct into a base64 URL-encoded string.
func (t *TransactionData) Base64Encode() (string, error) {
	bJSON, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(bJSON)
	if encoded == "" {
		return "", nil
	}

	return encoded, nil
}
