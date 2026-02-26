package openid4vci

//"client_id=1003&grant_type=authorization_code&code=b4af17ce-1c56-4546-9118-d60f6b301e44&code_verifier=vXshCcXYcceHZWukHCOVTN2WhXTJujgblBuokp8ofUw&redirect_uri=https%3A%2F%2Fdev.wallet.sunet.se"}

// TokenRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-token-request
type TokenRequest struct {
	// Header field
	DPOP string `header:"dpop" validate:"required"`

	// Pre-Authorized Code Flow
	// PreAuthorizedCode The code representing the authorization to obtain Credentials of a certain type. This parameter MUST be present if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.
	//PreAuthorizedCode string `json:"pre_authorized_code,omitempty" validate:"required_with=GrantType"`

	//// TXCode OPTIONAL. String value containing a Transaction Code. This value MUST be present if a tx_code object was present in the Credential Offer (including if the object was empty). This parameter MUST only be used if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.
	//TXCode string `json:"tx_code" validate:"required_unless=GrantType urn:ietf:params:oauth:grant-type:pre-authorized_code"`

	//// Authorization Code Flow
	//// GrantType REQUIRED.  Value MUST be set to "authorization_code".
	GrantType string `form:"grant_type" json:"grant_type" validate:"required,oneof=authorization_code"`

	//// Code REQUIRED.  The authorization code received from the authorization server.
	Code string `form:"code" json:"code" validate:"required"`

	//// RedirectURI	REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.
	RedirectURI string `form:"redirect_uri" json:"redirect_uri" validate:"required"`

	//// ClientID REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.
	ClientID string `form:"client_id" json:"client_id" validate:"required"`

	//// CodeVerifier OPTIONAL (required for public clients)
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
}

// TokenResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-successful-token-response
type TokenResponse struct {
	// AccessToken REQUIRED.  The access token issued by the authorization server.
	AccessToken string `json:"access_token" validate:"required"`

	// TokenType REQUIRED.  The type of the token issued as described in Section 7.1.  Value is case insensitive.
	TokenType string `json:"token_type" validate:"required"`

	// ExpiresIn RECOMMENDED.  The lifetime in seconds of the access token.  For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated. If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value.
	ExpiresIn int `json:"expires_in" validate:"required"`

	// Scope OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.  The scope of the access token as described by Section 3.3.
	Scope string `json:"scope"`

	// State REQUIRED if the "state" parameter was present in the client authorization request.  The exact value received from the client.
	State string `json:"state"`

	//CNonce OPTIONAL. String containing a nonce to be used when creating a proof of possession of the key proof (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce"`

	// CNonceExpiresIn OPTIONAL. Number denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in"`

	// AuthorizationDetails REQUIRED when authorization_details parameter is used to request issuance of a certain Credential type as defined in Section 5.1.1. It MUST NOT be used otherwise. It is an array of objects, as defined in Section 7 of [RFC9396]. In addition to the parameters defined in Section 5.1.1, this specification defines the following parameter to be used with the authorization details type openid_credential in the Token Response:
	// * credential_identifiers: OPTIONAL. Array of strings, each uniquely identifying a Credential that can be issued using the Access Token returned in this response. Each of these Credentials corresponds to the same entry in the credential_configurations_supported Credential Issuer metadata but can contain different claim values or a different subset of claims within the claims set identified by that Credential type. This parameter can be used to simplify the Credential Request, as defined in Section 7.2, where the credential_identifier parameter replaces the format parameter and any other Credential format-specific parameters in the Credential Request. When received, the Wallet MUST use these values together with an Access Token in subsequent Credential Requests.

	AuthorizationDetails []AuthorizationDetailsParameter `json:"authorization_details"`
}

func (t *TokenResponse) DpopResponse() error {
	return nil
}
