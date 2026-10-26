package configuration

import (
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// checkClaimOpenings refuses a claim opening whose claim reaches the
// credential, where its secret would be in the clear.
func checkClaimOpenings(src model.SourceScope, meta *model.CredentialMetadata) error {
	for i, d := range src.Derivations {
		if d.HashCommitment == nil || d.HashCommitment.Opening.Claim == nil {
			continue
		}
		if err := checkClaimSecret(src, meta, d.HashCommitment.Opening.Claim.Input); err != nil {
			return fmt.Errorf("%s.derivations[%d].hash_commitment.opening.claim: %w", src.Where(), i, err)
		}
	}
	return nil
}

// checkClaimSecret refuses a claim that reaches the credential: the
// credential carries it, or a derivation reads it.
func checkClaimSecret(src model.SourceScope, meta *model.CredentialMetadata, claim string) error {
	if err := checkClaimWithheld(meta, src.Source, claim); err != nil {
		return err
	}
	return checkClaimUnread(src.Derivations, claim)
}

// checkClaimWithheld refuses a source claim the issued credential carries.
// An mdoc carries each document key its MDDL declares as an element. An
// SD-JWT VC from a presentation carries the claims its VCTM declares, and
// one from any other source its whole document.
func checkClaimWithheld(meta *model.CredentialMetadata, source model.DataSourceType, claim string) error {
	switch {
	case meta.Format == openid4vp.FormatMsoMdoc:
		if element, ok := mddlElementHolding(meta.MDDL, claim); ok {
			return fmt.Errorf("the credential carries claim %q: the MDDL declares element %q", claim, element)
		}
	case source == model.DataSourcePresentation:
		if vctmDeclares(meta.GetVCTM(), claim) {
			return fmt.Errorf("the credential carries claim %q: the VCTM declares it", claim)
		}
	default:
		return fmt.Errorf("the credential carries claim %q: an SD-JWT VC from the %s source carries its whole document", claim, source)
	}
	return nil
}

// mddlElementHolding returns the MDDL element at the document key that
// holds claim: the claim as one literal key, or the first segment of its
// dotted path.
func mddlElementHolding(mddl *mdoc.MDDLSchema, claim string) (string, bool) {
	if mddl == nil {
		return "", false
	}
	keys := []string{claim}
	if first, _, dotted := strings.Cut(claim, "."); dotted {
		keys = append(keys, first)
	}
	for _, elements := range mddl.Claims {
		for _, key := range keys {
			if _, ok := elements[key]; ok {
				return key, true
			}
		}
	}
	return "", false
}

// vctmDeclares reports whether the VCTM filter keeps the claim or a value
// holding it: a VCTM claim path and the claim's path agree on their common
// prefix. The claim's path is its dotted segments, or the claim as one
// literal key.
func vctmDeclares(vctm *sdjwtvc.VCTM, claim string) bool {
	if vctm == nil {
		return false
	}
	for _, declared := range vctm.Claims {
		if pathsOverlap(declared.Path, strings.Split(claim, ".")) || pathsOverlap(declared.Path, []string{claim}) {
			return true
		}
	}
	return false
}

// pathsOverlap reports whether one path is a prefix of the other. A null
// segment of the VCTM path matches any segment.
func pathsOverlap(declared []*string, segments []string) bool {
	for i := range min(len(declared), len(segments)) {
		if declared[i] != nil && *declared[i] != segments[i] {
			return false
		}
	}
	return true
}

// checkClaimUnread refuses a derivation that reads the claim or a value
// holding it. Its output is the secret, or a function of it, in the
// credential's document.
func checkClaimUnread(derivations []primitives.Derivation, claim string) error {
	for i, d := range derivations {
		if input := d.InputClaim(); input != "" && claimPathsOverlap(input, claim) {
			return fmt.Errorf("derivations[%d] reads claim %q into the credential's document", i, claim)
		}
	}
	return nil
}

// claimPathsOverlap reports whether one dotted claim path is the other or
// holds it.
func claimPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(b, a+".") || strings.HasPrefix(a, b+".")
}
