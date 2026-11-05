package openid4vci

// MarshalLog returns the non-secret fields of a TokenResponse for logging:
// token type, scope, state, expiries, the number of authorization details,
// and whether each token and the c_nonce are set. zapr calls it for every
// call site that logs a TokenResponse.
//
// Value receiver, for the reason cache.AuthorizationContext.MarshalLog
// gives: a pointer receiver leaves a logged TokenResponse VALUE on
// zapr's reflection path, where the access token and the refresh token
// are printed in full.
func (t TokenResponse) MarshalLog() any {
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
