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
func (v *VPResponse) MarshalLog() any {
	if v == nil {
		return nil
	}
	return map[string]any{
		"state":    v.State,
		"vp_token": v.VPTokenSummary(),
	}
}
