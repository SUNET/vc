package configuration

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// checkOpeningClaims checks the claims of the source data each opening of
// src reads.
func checkOpeningClaims(cfg *model.Cfg, src model.SourceScope, meta *model.CredentialMetadata) error {
	for i, d := range src.Derivations {
		if d.HashCommitment == nil {
			continue
		}
		opening := d.HashCommitment.Opening
		generator, inputs, err := opening.Inputs()
		if err != nil {
			return fmt.Errorf("%s.derivations[%d].hash_commitment.opening: %w", src.Where(), i, err)
		}
		if err := checkOpeningInputs(cfg, src, meta, opening, inputs); err != nil {
			return fmt.Errorf("%s.derivations[%d].hash_commitment.opening.%s: %w", src.Where(), i, generator, err)
		}
	}
	return nil
}

// checkOpeningInputs keeps a claim opening's claim out of the credential,
// and requires a presentation to require each input.
func checkOpeningInputs(cfg *model.Cfg, src model.SourceScope, meta *model.CredentialMetadata, opening primitives.OpeningArgs, inputs []claimpath.Ref) error {
	if opening.Claim != nil {
		if err := checkClaimSecret(cfg, src, meta, opening.Claim.Input.Path); err != nil {
			return err
		}
	}
	return checkInputsRequired(src, inputs)
}

// checkInputsRequired refuses an input a presentation source does not
// require: its source data holds the required claims alone.
func checkInputsRequired(src model.SourceScope, inputs []claimpath.Ref) error {
	if src.Source != model.DataSourcePresentation {
		return nil
	}
	for _, input := range inputs {
		if !slices.ContainsFunc(src.RequiredClaims, func(r model.RequiredClaim) bool { return r.Path.Equal(input.Path) }) {
			return fmt.Errorf("input %s is the path of no required_claims entry", input)
		}
	}
	return nil
}

// checkClaimSecret refuses a claim that reaches the credential: the
// credential carries it, or a derivation reads it.
func checkClaimSecret(cfg *model.Cfg, src model.SourceScope, meta *model.CredentialMetadata, claim claimpath.Pointer) error {
	shapes, err := cfg.DerivationShapes(src)
	if err != nil {
		return err
	}
	location, err := shapes.Source.Locate(claim)
	if err != nil {
		return fmt.Errorf("claim %s: %w", claim, err)
	}
	if err := checkClaimWithheld(meta, src.Source, claim, location); err != nil {
		return err
	}
	return checkClaimUnread(src.Derivations, claim)
}

// checkClaimWithheld refuses a source claim the issued credential carries.
// location is where the source data holds the claim. An mdoc carries each
// document key its MDDL declares as an element. An SD-JWT VC from a
// presentation carries the claims its VCTM declares, and one from any other
// source its whole document.
func checkClaimWithheld(meta *model.CredentialMetadata, source model.DataSourceType, claim, location claimpath.Pointer) error {
	switch {
	case meta.Format == openid4vp.FormatMsoMdoc:
		if element, ok := mddlElementHolding(meta.MDDL, location); ok {
			return fmt.Errorf("the credential carries claim %s: the MDDL declares element %q", claim, element)
		}
	case source == model.DataSourcePresentation:
		if vctmDeclares(meta.GetVCTM(), location) {
			return fmt.Errorf("the credential carries claim %s: the VCTM declares it", claim)
		}
	default:
		return fmt.Errorf("the credential carries claim %s: an SD-JWT VC from the %s source carries its whole document", claim, source)
	}
	return nil
}

// mddlElementHolding returns the MDDL element at the document key that
// holds the claim at location: its first key.
func mddlElementHolding(mddl *mdoc.MDDLSchema, location claimpath.Pointer) (string, bool) {
	key, ok := location.FirstKey()
	if mddl == nil || !ok {
		return "", false
	}
	for _, elements := range mddl.Claims {
		if _, declared := elements[key]; declared {
			return key, true
		}
	}
	return "", false
}

// vctmDeclares reports whether the VCTM filter keeps the claim at location
// or a value holding it: a VCTM claim path and location agree on their
// common prefix.
func vctmDeclares(vctm *sdjwtvc.VCTM, location claimpath.Pointer) bool {
	if vctm == nil {
		return false
	}
	for _, declared := range vctm.Claims {
		if pathsOverlap(declared.Path, location) {
			return true
		}
	}
	return false
}

// pathsOverlap reports whether one path is a prefix of the other. A null
// component of the VCTM path matches any component.
func pathsOverlap(declared, location claimpath.Pointer) bool {
	a, errA := declared.Components()
	b, errB := location.Components()
	if errA != nil || errB != nil {
		return false
	}
	for i := range min(len(a), len(b)) {
		if !a[i].IsAll() && a[i] != b[i] {
			return false
		}
	}
	return true
}

// checkClaimUnread refuses a derivation that reads the claim or a value
// holding it. Its output is the secret, or a function of it, in the
// credential's document.
func checkClaimUnread(derivations []primitives.Derivation, claim claimpath.Pointer) error {
	for i, d := range derivations {
		if input, ok := d.Input(); ok && (input.Path.HasPrefix(claim) || claim.HasPrefix(input.Path)) {
			return fmt.Errorf("derivations[%d] reads claim %s into the credential's document", i, claim)
		}
	}
	return nil
}
