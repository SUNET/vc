package authzen

// Machine-readable evaluation status carried in EvaluationResponseContext.Reason.
//
// A denial has two very different meanings. "Evaluated: not trusted" means
// every applicable registry answered and none trusted the subject. "Could not
// evaluate" means at least one applicable registry failed to answer (error,
// timeout, panic, open circuit breaker), so a registry that might have trusted
// the subject was not consulted. Both are decision:false, so clients that read
// only the decision are unaffected; clients that fall back to another policy
// only on failure (never on a denial) test ReasonKeyEvaluationStatus.
const (
	// ReasonKeyEvaluationStatus is the reason member that carries the status.
	// It is present only when the status is EvaluationStatusError.
	ReasonKeyEvaluationStatus = "evaluation_status"
	// ReasonKeyEvaluationErrors lists the failed registries as
	// [{"registry": name, "error": text}], for operators and logs.
	ReasonKeyEvaluationErrors = "evaluation_errors"

	// EvaluationStatusError marks a denial that is not a trust verdict.
	EvaluationStatusError = "error"
)

// CouldNotEvaluate reports whether r is a denial that carries the
// EvaluationStatusError marker, that is, a failure to evaluate rather than an
// "evaluated: not trusted" verdict. An allow is never a failure.
func (r *EvaluationResponse) CouldNotEvaluate() bool {
	if r == nil || r.Decision || r.Context == nil {
		return false
	}
	s, _ := r.Context.Reason[ReasonKeyEvaluationStatus].(string)
	return s == EvaluationStatusError
}
