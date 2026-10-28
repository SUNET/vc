package openid4vci

// MarshalLog returns what a TokenResponse may appear as in a log.
//
// Never access_token, refresh_token or c_nonce. The first two are bearer
// credentials, and the nonce is what binds a key proof to this exchange -
// a reader of the log who has all three can mint credential requests as
// the wallet.
//
// Implemented on the type rather than fixed at the call sites because a
// reply is logged whole in several places and the next one will be too;
// zapr invokes logr.Marshaler before it reflects over a value, so this
// decides the representation for all of them at once.
//
// What remains answers the operational questions - did a token come back,
// for what scope, how long is it good for - without answering "what is
// it".
func (t *TokenResponse) MarshalLog() any {
	if t == nil {
		return nil
	}
	return map[string]any{
		"token_type":               t.TokenType,
		"expires_in":               t.ExpiresIn,
		"scope":                    t.Scope,
		"state":                    t.State,
		"c_nonce_expires_in":       t.CNonceExpiresIn,
		"refresh_token_expires_in": t.RefreshTokenExpiresIn,
		"has_access_token":         t.AccessToken != "",
		"has_refresh_token":        t.RefreshToken != "",
		"has_c_nonce":              t.CNonce != "",
		"authorization_details":    len(t.AuthorizationDetails),
	}
}
