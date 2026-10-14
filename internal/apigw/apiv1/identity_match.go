package apiv1

import (
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vci"
)

// errIdentityMismatch is returned when a presented credential does not
// satisfy the rule the issuance was prepared with.
//
// A sentinel so the caller can answer differently from the way it answers
// a malformed or unverifiable presentation: this one verified perfectly
// and belongs to the wrong person.
var errIdentityMismatch = errors.New("the presented credential does not identify the Holder this issuance was prepared for")

// matchPresentedIdentity evaluates the caller-supplied rule against the
// claims of a verified presentation.
//
// Reached only after the presentation has been verified - its signature,
// its issuer's trust chain, its binding to this exchange - because a rule
// evaluated against unverified claims tests nothing but what the sender
// chose to write.
//
// Claim paths are resolved with lookupClaimPath, the same format-aware
// lookup the presentation scopes use, so a caller writes the same path
// here that it would write anywhere else and an mdoc's literal
// namespace-qualified key keeps working.
//
// Neither the returned error NOR the log names the values. The error is
// handed back to whoever is holding the wallet, and telling them which of
// several candidate identities the issuance was prepared for would turn a
// failed match into an oracle for the portal session's contents.
//
// The log is not a safer place for them. These values are names and
// national identifiers - the expected one taken from the portal session,
// the presented one read out of someone's credential - and writing them
// at Info puts both into log retention, log shipping and everything with
// read access to either, which is what SECURITY_HARDENING_PLAN.md's first
// phase exists to stop. The claim path is what makes a failure
// diagnosable; the values only make it quotable.
func (c *Client) matchPresentedIdentity(sourceFormat string, presented map[string]any, match *openid4vci.IdentityMatch) error {
	if match == nil {
		// Nothing to check. The decision that an issuance may be prepared
		// without a rule belongs to whoever accepted it - see
		// IdentityMatch.Validate, which refuses an EMPTY rule precisely so
		// that "no rule" has to be deliberate.
		return nil
	}

	for _, path := range match.ClaimPaths() {
		test := match.Claims[path]

		value, present := lookupClaimPath(sourceFormat, presented, path)
		if !present {
			c.log.Info("identity match failed: claim absent from the presented credential", "claim", path)
			return fmt.Errorf("%w: claim %q is not present", errIdentityMismatch, path)
		}

		if !claimValueMatches(value, []string{test.Equals}) {
			c.log.Info("identity match failed: claim value differs", "claim", path)
			return fmt.Errorf("%w: claim %q does not match", errIdentityMismatch, path)
		}
	}

	return nil
}
