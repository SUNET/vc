package cache

// Secret-bearing types render redacted in a log, wherever they are
// logged from.
//
// Naming safe fields at each call site works until the next call site.
// This repository had fourteen places handing a whole request, reply or
// context to the logger, and the ones that leaked were not obviously
// different from the ones that did not - the leak is in what the struct
// happens to carry, which is invisible at the call site.
//
// zapr invokes logr.Marshaler before it reflects over a value
// (vendor/github.com/go-logr/zapr/zapr.go, invokeMarshaler), so a type
// that implements MarshalLog decides its own log representation once,
// for every caller that exists now or later.

// MarshalLog returns what an AuthorizationContext may appear as in a log.
//
// Never the credentials it carries - Token.AccessToken, AccessToken,
// RefreshToken, IDToken, Code, TXCode, VPToken - and never
// VerifiedClaims, which are the holder's own data. A token in a log is a
// replayable credential, and a log outlives the token's usefulness to its
// owner but not to a reader of the log.
//
// What is left is what a log is for: which session, what state, which
// scopes, and whether the secret-bearing fields were populated at all -
// the last of those answers "did the token endpoint run" without
// answering "with what".
func (a *AuthorizationContext) MarshalLog() any {
	if a == nil {
		return nil
	}
	return map[string]any{
		"session_id":          a.SessionID,
		"status":              a.Status,
		"scopes":              a.Scopes,
		"client_id":           a.ClientID,
		"expires_at":          a.ExpiresAt,
		"has_access_token":    a.AccessToken != "" || (a.Token != nil && a.Token.AccessToken != ""),
		"has_refresh_token":   a.RefreshToken != "",
		"has_code":            a.Code != "",
		"verified_claim_keys": claimKeys(a.VerifiedClaims),
	}
}

// claimKeys names the verified claims without their values: which claims
// a presentation supplied is operationally useful, what they say is the
// holder's business.
func claimKeys(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	return keys
}
