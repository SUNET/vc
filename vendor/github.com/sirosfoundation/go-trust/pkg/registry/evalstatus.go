package registry

import "github.com/sirosfoundation/go-trust/pkg/authzen"

// markEvaluationFailures flags a denial as "could not evaluate" when any
// consulted registry failed to answer. The strategies record such a registry as
// an entry with an "error" member in registry_results (first_match, sequential)
// or all_results (all, best_match); a registry that answered with a denial has
// a "decision" member instead, and a composite with a failed child says so in
// its nested reason. The check runs once in dispatch so every
// strategy is covered the same way. Allow responses are left untouched: a
// positive match stands even if another registry failed.
func markEvaluationFailures(resp *authzen.EvaluationResponse) {
	if resp == nil || resp.Decision || resp.Context == nil || resp.Context.Reason == nil {
		return
	}
	reason := resp.Context.Reason
	var failed []map[string]interface{}
	for _, key := range []string{"registry_results", "all_results"} {
		entries, _ := reason[key].([]map[string]interface{})
		for _, e := range entries {
			name, _ := e["registry"].(string)
			msg, isErr := e["error"].(string)
			if !isErr {
				inner, _ := e["reason"].(map[string]interface{})
				incomplete, _ := inner["incomplete"].(bool)
				_, decided := e["decision"].(bool)
				switch {
				case incomplete:
					// A composite whose child failed answers with a denial of its
					// own and marks it incomplete (see CompositeRegistry); a
					// registry whose data is not available yet (the whitelist's
					// JWKS cache) does the same and names the cause.
					msg = "a child registry failed to answer"
					if cause, ok := inner["error"].(string); ok && cause != "" {
						msg = cause
					}
				case !decided:
					// A (nil, nil) answer supplies no verdict.
					msg = "registry returned no decision"
				default:
					continue
				}
			}
			failed = append(failed, map[string]interface{}{"registry": name, "error": msg})
		}
	}
	if len(failed) == 0 {
		return
	}
	reason[authzen.ReasonKeyEvaluationStatus] = authzen.EvaluationStatusError
	reason[authzen.ReasonKeyEvaluationErrors] = failed
}
