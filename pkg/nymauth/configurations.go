package nymauth

// Pseudonym configurations from the rulebook's function catalogue.
//
// The configuration decides the pseudonym's domain separator, so a
// pseudonym under one configuration is unrelated to the same subject's
// pseudonym under another. A verifier's circuit allowlist names one per
// entry, and refuses a configuration it does not recognise rather than
// loading a circuit it cannot reason about.
//
// Only the two known-offender-matching configurations are named here,
// because they are the two anything in this repository still refers to.
// The catalogue also defines account-recovery-ssc and
// user-managed-pseudonym-xsite-ssc; their only callers were the
// issuer-side seed tooling that Credential Auxiliary Data replaces, so
// naming them here would be a vocabulary with nothing to say it.
const (
	ConfigKnownOffenderMatchingSSC = "known-offender-matching-ssc"
	ConfigKnownOffenderMatchingPSC = "known-offender-matching-psc"
)
