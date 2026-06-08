package openid4vci

//"client_id=1003&grant_type=authorization_code&code=b4af17ce-1c56-4546-9118-d60f6b301e44&code_verifier=vXshCcXYcceHZWukHCOVTN2WhXTJujgblBuokp8ofUw&redirect_uri=https%3A%2F%2Fdev.wallet.sunet.se"}

// TokenRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
type TokenRequest struct {
	// Header field
	DPOP string `header:"dpop"`

	// GrantType REQUIRED. "authorization_code" or "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	GrantType string `form:"grant_type" json:"grant_type" validate:"required,oneof=authorization_code urn:ietf:params:oauth:grant-type:pre-authorized_code"`

	// Authorization Code Flow fields

	// Code REQUIRED for authorization_code grant. The authorization code received from the authorization server.
	Code string `form:"code" json:"code" validate:"required_if=GrantType authorization_code,omitempty,max=128,printascii"`

	// RedirectURI REQUIRED for authorization_code grant, if the "redirect_uri" parameter was included in the authorization request.
	RedirectURI string `form:"redirect_uri" json:"redirect_uri"`

	// ClientID REQUIRED for authorization_code grant when not using client assertion authentication (RFC 6749 §4.1.3).
	// When using private_key_jwt or client_secret_jwt, client_id is conveyed via the assertion's "sub" claim.
	// OPTIONAL for pre-authorized_code grant.
	ClientID string `form:"client_id" json:"client_id" validate:"omitempty,max=128,printascii"`

	// CodeVerifier OPTIONAL (required for public clients using authorization_code grant)
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`

	// ClientAssertionType OPTIONAL. The type of client assertion. For private_key_jwt: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
	ClientAssertionType string `form:"client_assertion_type" json:"client_assertion_type" validate:"omitempty,max=256,printascii"`

	// ClientAssertion OPTIONAL. The client assertion JWT for private_key_jwt or client_secret_jwt authentication.
	ClientAssertion string `form:"client_assertion" json:"client_assertion" validate:"omitempty,max=8192,printascii"`

	// Pre-Authorized Code Flow fields

	// PreAuthorizedCode REQUIRED for pre-authorized_code grant. The code representing the authorization to obtain Credentials.
	PreAuthorizedCode string `form:"pre-authorized_code" json:"pre-authorized_code" validate:"required_if=GrantType urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty,max=128,printascii"`

	// TXCode OPTIONAL. String value containing a Transaction Code.
	TXCode string `form:"tx_code" json:"tx_code"`
}

// TokenResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response
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

	// CNonce OPTIONAL. String containing a nonce to be used when creating a proof of possession of the key proof (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce"`

	// CNonceExpiresIn OPTIONAL. Number denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in"`

	// AuthorizationDetails REQUIRED when authorization_details parameter is used in either the Authorization Request or Token Request.
	// OPTIONAL when scope parameter was used to request issuance of a Credential. It MUST NOT be used otherwise.
	// It is a non-empty array of objects, as defined in Section 7 of [RFC9396].
	AuthorizationDetails []AuthorizationDetailsParameter `json:"authorization_details,omitempty"`
}
