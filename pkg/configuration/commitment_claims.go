package configuration

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// checkCommitmentClaim accepts an entry whose claim the credential's type
// metadata declares, in the representation the entry's encoding names.
func checkCommitmentClaim(meta *model.CredentialMetadata, entry openid4vci.AuxiliaryDataEntry) error {
	if entry.Encoding != "" {
		if _, err := openid4vci.EncodeCommitment(entry.Encoding, nil); err != nil {
			return err
		}
	}
	switch {
	case meta.Format == openid4vp.FormatMsoMdoc:
		return checkMDocCommitmentClaim(meta.MDDL, entry.Path, entry.Encoding)
	case openid4vp.IsSDJWTVCCredentialFormat(meta.Format) && entry.Encoding == "":
		return fmt.Errorf("path %q: an SD-JWT VC claim holds text, so the entry needs an encoding", entry.Path)
	case openid4vp.IsSDJWTVCCredentialFormat(meta.Format):
		return checkSDJWTCommitmentClaim(meta.GetVCTM(), entry.Path)
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
	claim, ok := meta.GetVCTM().ClaimAt(path)
	return ok && claim.Mandatory
}

// claimDeclared reports whether the type metadata declares a claim at
// path.
func claimDeclared(meta *model.CredentialMetadata, path []string) bool {
	if meta.Format == openid4vp.FormatMsoMdoc {
		_, ok := mddlElement(meta.MDDL, path)
		return ok
	}
	_, ok := meta.GetVCTM().ClaimAt(path)
	return ok
}

// checkMDocCommitmentClaim accepts an element of the MDDL that holds the
// commitment's bytes as a bstr, or its text in an encoding as a tstr.
func checkMDocCommitmentClaim(mddl *mdoc.MDDLSchema, path []string, encoding string) error {
	if len(path) != 2 {
		return fmt.Errorf("path %q is a namespace and an element", path)
	}
	claim, ok := mddlElement(mddl, path)
	if !ok {
		return fmt.Errorf("the MDDL declares no element at path %q", path)
	}
	want, held := "bstr", "bytes"
	if encoding != "" {
		want, held = "tstr", encoding+" text"
	}
	if claim.ValueType != want {
		return fmt.Errorf("path %q is a %s element; a commitment in %s needs a %s element", path, claim.ValueType, held, want)
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
	claim, ok := vctm.ClaimAt(path)
	switch {
	case !ok:
		return fmt.Errorf("the VCTM declares no claim at path %q", path)
	case claim.SD != "always":
		return fmt.Errorf("the VCTM declares path %q with sd %q; a commitment needs sd \"always\", so the holder can withhold it", path, claim.SD)
	}
	for _, other := range vctm.Claims {
		if len(other.Path) > len(path) && sdjwtvc.ClaimPathHasPrefix(other.Path, path) {
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
