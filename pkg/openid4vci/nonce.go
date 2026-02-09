package openid4vci

// NonceResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response
type NonceResponse struct {
	CNonce string `json:"c_nonce"`
}
