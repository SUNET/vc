package openid4vp

// VPTokenSummary returns, per credential query id, the byte length of each
// presentation. A vp_token holds the holder's presented credentials in the
// clear, so logs carry this summary in its place.
func (v *VPResponse) VPTokenSummary() map[string][]int {
	if v == nil || len(v.VPToken) == 0 {
		return nil
	}
	out := make(map[string][]int, len(v.VPToken))
	for queryID, presentations := range v.VPToken {
		lengths := make([]int, 0, len(presentations))
		for _, p := range presentations {
			lengths = append(lengths, len(p))
		}
		out[queryID] = lengths
	}
	return out
}

// MarshalLog returns the log form of a VPResponse: its state and
// VPTokenSummary.
//
// Value receiver, and this is the one where it matters most: three
// handlers hold a VPResponse as a value rather than a pointer
// (handler_oidc.go, handlers_verification.go, handlers_verifier.go) and
// vpTokensForScope takes one as a value parameter, so the dereferenced
// spelling is not hypothetical here - it is what the code already has in
// hand. A vp_token holds the holder's presented credentials in the
// clear. See cache.AuthorizationContext.MarshalLog for the nil trade.
func (v VPResponse) MarshalLog() any {
	return map[string]any{
		"state":    v.State,
		"vp_token": v.VPTokenSummary(),
	}
}
