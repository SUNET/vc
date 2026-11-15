package cache

// An outcome is final, and the FIRST one wins.
//
// Two requests can reach a session at once: a wallet's error response and
// the presentation it was racing. Each used to read the context, decide it
// was still open, and save its own copy - a read, a decision and a write
// with no lock across them. Whichever saved last won, and the loser's
// outcome was erased after it had already been reported: a decline could
// be told to the browser and then overwritten by a presentation that had
// been verifying all along, leaving a session that said "complete" to one
// endpoint and "declined" to another.
//
// ClaimOutcome closes that by making the check and the write one operation
// in the store. These two helpers are what "already has an outcome" means,
// and they live here rather than beside either caller so both sides of the
// race agree on it.

// SessionStatusIsTerminal reports whether a status is one a session cannot
// leave.
func SessionStatusIsTerminal(status SessionStatus) bool {
	switch status {
	case SessionStatusCodeIssued, SessionStatusTokenIssued,
		SessionStatusCompleted, SessionStatusError,
		SessionStatusExpired:
		return true
	}
	return false
}

// HasOutcome reports whether a context has already reached one.
//
// VerifierResponseCode counts even when the status does not: it is minted
// as a presentation completes, and a session carrying one has handed the
// browser something to fetch with.
func HasOutcome(doc *AuthorizationContext) bool {
	if doc == nil {
		return false
	}
	return SessionStatusIsTerminal(doc.Status) || doc.VerifierResponseCode != ""
}
