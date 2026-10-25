package configuration

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
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
	if !entry.Path.SelectsOne() {
		return fmt.Errorf("path %s names no single claim to hold the commitment", entry.Path)
	}
	switch {
	case meta.Format == openid4vp.FormatMsoMdoc:
		return checkMDocCommitmentClaim(meta.MDDL, entry.Path, entry.Encoding)
	case openid4vp.IsSDJWTVCCredentialFormat(meta.Format) && entry.Encoding == "":
		return fmt.Errorf("path %s: an SD-JWT VC claim holds text, so the entry needs an encoding", entry.Path)
	case openid4vp.IsSDJWTVCCredentialFormat(meta.Format):
		return checkSDJWTCommitmentClaim(meta.GetVCTM(), entry.Path)
	}
	return fmt.Errorf("auxiliary data is implemented for %s and %s credentials", openid4vp.FormatMsoMdoc, openid4vp.FormatSDJWTVC)
}

// claimMandatory reports whether the type metadata makes the claim at path
// mandatory.
func claimMandatory(meta *model.CredentialMetadata, path claimpath.Pointer) bool {
	if meta.Format == openid4vp.FormatMsoMdoc {
		claim, ok := mddlElement(meta.MDDL, path)
		return ok && claim.Mandatory
	}
	claim, ok := vctmClaim(meta.GetVCTM(), path)
	return ok && claim.Mandatory
}

// checkMDocCommitmentClaim accepts an element of the MDDL that holds the
// commitment's bytes as a bstr, or its text in an encoding as a tstr.
func checkMDocCommitmentClaim(mddl *mdoc.MDDLSchema, path claimpath.Pointer, encoding string) error {
	if _, _, err := path.MDoc(); err != nil {
		return err
	}
	claim, ok := mddlElement(mddl, path)
	if !ok {
		return fmt.Errorf("the MDDL declares no element at path %s", path)
	}
	want, held := "bstr", "bytes"
	if encoding != "" {
		want, held = "tstr", encoding+" text"
	}
	if claim.ValueType != want {
		return fmt.Errorf("path %s is a %s element; a commitment in %s needs a %s element", path, claim.ValueType, held, want)
	}
	return nil
}

// mddlElement returns the element of the MDDL at a namespace and element
// path.
func mddlElement(mddl *mdoc.MDDLSchema, path claimpath.Pointer) (mdoc.ClaimMetadata, bool) {
	namespace, element, err := path.MDoc()
	if mddl == nil || err != nil {
		return mdoc.ClaimMetadata{}, false
	}
	claim, ok := mddl.Claims[namespace][element]
	return claim, ok
}

// sdjwtBuilderClaims are the claims the SD-JWT builder writes at the root
// of the payload after it reads the document, replacing a commitment there.
// TestSDJWTBuilderClaimsCoverTheBuilder derives them from the builder.
var sdjwtBuilderClaims = []string{"iat", "nbf", "exp", "iss", "jti", "vct", "vct#integrity", "cnf", "status", "_sd_alg", "_sd"}

// checkSDJWTCommitmentClaim accepts a claim the VCTM declares with sd
// "always", so the holder can withhold the commitment, outside the claims
// the SD-JWT builder writes, with nothing declared beneath it.
func checkSDJWTCommitmentClaim(vctm *sdjwtvc.VCTM, path claimpath.Pointer) error {
	if err := checkSDJWTClaimName(path); err != nil {
		return err
	}
	claim, ok := vctmClaim(vctm, path)
	switch {
	case !ok:
		return fmt.Errorf("the VCTM declares no claim at path %s", path)
	case claim.SD != "always":
		return fmt.Errorf("the VCTM declares path %s with sd %q; a commitment needs sd \"always\", so the holder can withhold it", path, claim.SD)
	}
	for _, other := range vctm.Claims {
		if other.Path.Len() > path.Len() && other.Path.HasPrefix(path) {
			return fmt.Errorf("the VCTM declares a claim beneath path %s, where the commitment is a string", path)
		}
	}
	return nil
}

// checkSDJWTClaimName refuses a path the SD-JWT builder writes or a
// verifier removes: a builder claim at the root, and the disclosure
// members "_sd", "..." and "_sd_alg" at any depth.
func checkSDJWTClaimName(path claimpath.Pointer) error {
	components, err := path.Components()
	if err != nil {
		return err
	}
	if root, ok := components[0].KeyName(); ok && slices.Contains(sdjwtBuilderClaims, root) {
		return fmt.Errorf("path %s: the SD-JWT builder writes %q", path, root)
	}
	for _, component := range components {
		if key, ok := component.KeyName(); ok && (key == "_sd" || key == "..." || key == "_sd_alg") {
			return fmt.Errorf("path %s: %q names no claim in an SD-JWT", path, key)
		}
	}
	return nil
}

// vctmClaim returns the claim the VCTM declares at path.
func vctmClaim(vctm *sdjwtvc.VCTM, path claimpath.Pointer) (sdjwtvc.Claim, bool) {
	if vctm == nil {
		return sdjwtvc.Claim{}, false
	}
	for _, claim := range vctm.Claims {
		if claim.Path.Equal(path) {
			return claim, true
		}
	}
	return sdjwtvc.Claim{}, false
}
