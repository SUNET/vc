package apiv1

import (
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/legacyclaims"
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
// A claim is located in the presented credential's shape, the same one
// the presentation scopes use. A dotted claim name a session of the
// earlier release holds reads the way that release read it for the
// presented format.
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
func (c *Client) matchPresentedIdentity(sourceFormat string, presented map[string]any, stored *openid4vci.StoredIdentityMatch) error {
	if stored == nil {
		// Nothing to check. The decision that an issuance may be prepared
		// without a rule belongs to whoever accepted it - see
		// IdentityMatch.Validate, which refuses an EMPTY rule precisely so
		// that "no rule" has to be deliberate.
		return nil
	}
	match, err := stored.Rule(presentedClaimReader(sourceFormat))
	if err != nil {
		return err
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
// in shape. A claim the presentation holds in another structure is
// absent, and so is a path the shape holds no claim at: a rule path of
// one key in an mdoc, which a scope accepting SD-JWT VCs and mdocs meets.
func presentedClaim(shape claimpath.Shape, presented map[string]any, path claimpath.Pointer) (any, bool, error) {
	if _, err := shape.LocateOne(path); err != nil {
		return nil, false, nil
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

// authScopeFormats returns the credential format of each auth scope of
// scope.
func (c *Client) authScopeFormats(scope string) map[string]string {
	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil {
		return nil
	}
	formats := make(map[string]string, len(vpAuth.AuthScopes))
	for authScope := range vpAuth.AuthScopes {
		formats[authScope] = c.cfg.GetFormatForScope(authScope)
	}
	return formats
}

// storedIdentityMatch returns the rule as the session of an issuance of
// scope stores it: in the earlier release's dotted names when every auth
// scope of scope reads each name as its claim, so a replica running that
// release reads the session.
func (c *Client) storedIdentityMatch(scope string, match *openid4vci.IdentityMatch) *openid4vci.StoredIdentityMatch {
	formats := c.authScopeFormats(scope)
	return match.Store(func(p claimpath.Pointer) (string, bool) {
		name := ""
		for _, format := range formats {
			n, ok := legacyclaims.PresentedName(format, p)
			if !ok || (name != "" && n != name) {
				return "", false
			}
			name = n
		}
		return name, name != ""
	})
}

// presentedClaimReader reads the earlier release's dotted name of a claim
// of a presented credential of format.
func presentedClaimReader(format string) func(string) (claimpath.Pointer, error) {
	return func(name string) (claimpath.Pointer, error) {
		return legacyclaims.PresentedClaim(format, name)
	}
}
