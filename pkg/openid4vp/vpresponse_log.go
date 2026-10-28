package openid4vp

// VPTokenSummary describes a vp_token without carrying it.
//
// A vp_token entry is the holder's presented credential, whole and in
// the clear - an SD-JWT presentation with its disclosures, or an mdoc
// device response. It is the single most sensitive thing that crosses
// this service, and it is the one thing a log must not keep: logs are
// read by more people than the verification path and kept longer than
// the presentation is useful.
//
// The questions the logs around it were asking are structural - which
// credential queries answered, how many presentations each carried, were
// they empty - and all of them are answerable from lengths. So this
// returns the query ids with the byte length of each presentation, and
// nothing else.
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

// MarshalLog keeps a whole VPResponse out of a log, for the call sites
// that hand one over rather than a field of one.
//
// See pkg/cache/authcontext_log.go for why the type decides this rather
// than each caller.
func (v *VPResponse) MarshalLog() any {
	if v == nil {
		return nil
	}
	return map[string]any{
		"state":    v.State,
		"vp_token": v.VPTokenSummary(),
	}
}
