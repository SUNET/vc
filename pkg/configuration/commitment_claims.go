package configuration

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// checkCommitmentClaim accepts a claim the credential's type metadata
// declares where its format can carry a hash commitment.
func checkCommitmentClaim(meta *model.CredentialMetadata, path []string) error {
	switch {
	case meta.Format == openid4vp.FormatMsoMdoc:
		return checkMDocCommitmentClaim(meta.MDDL, path)
	case openid4vp.IsSDJWTVCCredentialFormat(meta.Format):
		return checkSDJWTCommitmentClaim(meta.GetVCTM(), path)
	}
	return fmt.Errorf("auxiliary data is implemented for %s and %s credentials", openid4vp.FormatMsoMdoc, openid4vp.FormatSDJWTVC)
}

// claimMandatory reports whether the type metadata makes the claim at path
// mandatory.
func claimMandatory(meta *model.CredentialMetadata, path []string) bool {
	if meta.Format == openid4vp.FormatMsoMdoc {
		claim, ok := mddlElement(meta.MDDL, path)
		return ok && claim.Mandatory
	}
	claim, ok := vctmClaim(meta.GetVCTM(), path)
	return ok && claim.Mandatory
}

// checkMDocCommitmentClaim accepts a bstr element of the MDDL.
func checkMDocCommitmentClaim(mddl *mdoc.MDDLSchema, path []string) error {
	if len(path) != 2 {
		return fmt.Errorf("path %q is a namespace and an element", path)
	}
	claim, ok := mddlElement(mddl, path)
	if !ok {
		return fmt.Errorf("the MDDL declares no element at path %q", path)
	}
	if claim.ValueType != "bstr" {
		return fmt.Errorf("path %q is a %s element; a hash commitment is a bstr", path, claim.ValueType)
	}
	return nil
}

// mddlElement returns the element of the MDDL at a namespace and element
// path.
func mddlElement(mddl *mdoc.MDDLSchema, path []string) (mdoc.ClaimMetadata, bool) {
	if mddl == nil || len(path) != 2 {
		return mdoc.ClaimMetadata{}, false
	}
	claim, ok := mddl.Claims[path[0]][path[1]]
	return claim, ok
}

// sdjwtBuilderClaims are the claims the SD-JWT builder writes at the root
// of the payload after it reads the document, replacing a commitment there.
// TestSDJWTBuilderClaimsCoverTheBuilder derives them from the builder.
var sdjwtBuilderClaims = []string{"iat", "nbf", "exp", "iss", "jti", "vct", "vct#integrity", "cnf", "status", "_sd_alg", "_sd"}

// checkSDJWTCommitmentClaim accepts a claim the VCTM declares with sd
// "always", so the holder can withhold the commitment, outside the claims
// the SD-JWT builder writes, with nothing declared beneath it.
func checkSDJWTCommitmentClaim(vctm *sdjwtvc.VCTM, path []string) error {
	if err := checkSDJWTClaimName(path); err != nil {
		return err
	}
	claim, ok := vctmClaim(vctm, path)
	switch {
	case !ok:
		return fmt.Errorf("the VCTM declares no claim at path %q", path)
	case claim.SD != "always":
		return fmt.Errorf("the VCTM declares path %q with sd %q; a commitment needs sd \"always\", so the holder can withhold it", path, claim.SD)
	}
	for _, other := range vctm.Claims {
		if len(other.Path) > len(path) && claimPathHasPrefix(other.Path, path) {
			return fmt.Errorf("the VCTM declares a claim beneath path %q, where the commitment is a string", path)
		}
	}
	return nil
}

// checkSDJWTClaimName refuses a path the SD-JWT builder writes or a
// verifier removes: a builder claim at the root, and the disclosure
// members "_sd", "..." and "_sd_alg" at any depth.
func checkSDJWTClaimName(path []string) error {
	if slices.Contains(sdjwtBuilderClaims, path[0]) {
		return fmt.Errorf("path %q: the SD-JWT builder writes %q", path, path[0])
	}
	for _, segment := range path {
		if segment == "_sd" || segment == "..." || segment == "_sd_alg" {
			return fmt.Errorf("path %q: %q names no claim in an SD-JWT", path, segment)
		}
	}
	return nil
}

// vctmClaim returns the claim the VCTM declares at path.
func vctmClaim(vctm *sdjwtvc.VCTM, path []string) (sdjwtvc.Claim, bool) {
	if vctm == nil {
		return sdjwtvc.Claim{}, false
	}
	for _, claim := range vctm.Claims {
		if len(claim.Path) == len(path) && claimPathHasPrefix(claim.Path, path) {
			return claim, true
		}
	}
	return sdjwtvc.Claim{}, false
}

// claimPathHasPrefix reports whether a VCTM claim path starts with prefix.
func claimPathHasPrefix(claimPath []*string, prefix []string) bool {
	if len(claimPath) < len(prefix) {
		return false
	}
	for i, segment := range prefix {
		if claimPath[i] == nil || *claimPath[i] != segment {
			return false
		}
	}
	return true
}
