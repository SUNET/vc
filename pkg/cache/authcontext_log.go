package cache

import (
	"maps"
	"slices"
)

// Secret-bearing types implement logr.Marshaler, so every call site that
// logs them gets the redacted form: zapr calls MarshalLog before it
// reflects over a value.

// MarshalLog returns the non-secret fields of an AuthorizationContext for
// logging: session, status, scopes, client, expiry, whether each token and
// code is set, and the names of the verified claims.
//
// VALUE receiver, so the redaction applies however the context is spelled
// at the call site. A pointer receiver covers only the pointer: logging
// *authCtx - one character away from authCtx, and indistinguishable from
// it in review - puts zapr on the reflection path instead, where it walks
// the struct and prints the access token, the refresh token and every
// verified claim. A pointer's method set contains its value methods, so
// this covers both spellings and changes nothing at any call site that
// passes a pointer.
//
// The cost is the nil pointer, which used to render as null and now
// dereferences inside this method; zapr recovers that and records the
// panic in place of the field. That is the right way round. A nil context
// carries no secret, so the worst case is an unhelpful log line, while
// the case the value receiver covers carries all of them.
func (a AuthorizationContext) MarshalLog() any {
	return map[string]any{
		"session_id":          a.SessionID,
		"status":              a.Status,
		"scopes":              a.Scopes,
		"client_id":           a.ClientID,
		"expires_at":          a.ExpiresAt,
		"has_access_token":    a.AccessToken != "" || (a.Token != nil && a.Token.AccessToken != ""),
		"has_refresh_token":   a.RefreshToken != "",
		"has_id_token":        a.IDToken != "",
		"has_code":            a.Code != "",
		"has_tx_code":         a.TXCode != "",
		"has_vp_token":        a.VPToken != "",
		"verified_claim_keys": claimKeys(a.VerifiedClaims),
	}
}

// claimKeys returns the sorted names of the verified claims.
func claimKeys(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(claims))
}
