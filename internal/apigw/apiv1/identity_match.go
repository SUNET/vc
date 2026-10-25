package apiv1

import (
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/fxamacker/cbor/v2"
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
// A claim is read in the presented credential's shape, the same one the
// presentation scopes use, and a dotted claim path the way that format
// reads it, so a caller writes the same path here that it would write
// anywhere else and an mdoc's namespace-qualified claim keeps working.
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

	shape := openid4vp.PresentedShape(sourceFormat)
	for _, claim := range match.Claims {
		value, present, err := presentedClaim(shape, presented, claim.Path)
		if err != nil {
			return fmt.Errorf("identity match claim %s: %w", claim.Path, err)
		}
		if !present {
			c.log.Info("identity match failed: claim absent from the presented credential", "claim", claim.Path.String())
			return fmt.Errorf("%w: claim %s is not present", errIdentityMismatch, claim.Path)
		}
		if isMDocLikeFormat(sourceFormat) {
			value = unwrapMDocFullDate(value)
		}

		if !claimValueMatches(value, []string{claim.Equals}) {
			c.log.Info("identity match failed: claim value differs", "claim", claim.Path.String())
			return fmt.Errorf("%w: claim %s does not match", errIdentityMismatch, claim.Path)
		}
	}

	return nil
}

// presentedClaim returns the claim at a rule path in a presentation held
// in shape, with a dotted path read in shape. A claim the presentation
// holds in another structure is absent.
func presentedClaim(shape claimpath.Shape, presented map[string]any, path claimpath.Pointer) (any, bool, error) {
	if err := path.Resolve(shape.Dotted); err != nil {
		return nil, false, err
	}
	value, present, err := shape.Get(presented, path)
	if errors.Is(err, claimpath.ErrMismatch) {
		return nil, false, nil
	}
	return value, present, err
}

// unwrapMDocFullDate returns the string inside an mdoc full-date (CBOR tag
// 1004), which decodes into an `any` as a cbor.Tag and never equals a string.
func unwrapMDocFullDate(v any) any {
	switch d := v.(type) {
	case cbor.Tag:
		if s, ok := d.Content.(string); ok && d.Number == mdoc.TagDate {
			return s
		}
	case mdoc.FullDate:
		return string(d)
	}
	return v
}
