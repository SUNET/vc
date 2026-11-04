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
// Pointer receiver so a nil context (e.g. a failed Get) logs as null.
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
