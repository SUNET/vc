package apiv1

import (
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// buildPresentationDocument assembles document_data for a credential whose
// data source is presentation. Reads the presented credential's claims from
// authCtx.VerifiedClaims (populated by finalisePresentationVerification),
// runs the derivations configured for that presented credential via
// credential.ApplyDerivations, merges defaults, then filters against the
// target credential's VCTM, or its MDDL for mso_mdoc, so no non-declared
// PII survives into the derived credential.
func (c *Client) buildPresentationDocument(scope string, pScope model.PresentationScope, authCtx *cache.AuthorizationContext, now time.Time) (map[string]any, error) {
	if authCtx.VerifiedClaims == nil {
		return nil, errors.New("no verified presentation claims available for issuance")
	}
	accepted, ok := pScope.From[authCtx.PresentedScope]
	if !ok {
		return nil, fmt.Errorf("presentation scope %q accepts no %q credential", scope, authCtx.PresentedScope)
	}

	// Start from a deep copy of the verified presentation claims so a VCTM
	// claim that the presented credential already carries (and that no
	// derivation rewrites) still lands in the issued document. The VCTM
	// filter below drops anything the target credential does not declare.
	verified := storedClaims(authCtx.VerifiedClaims)
	doc := credential.CloneNestedClaims(verified)

	derived, err := credential.ApplyDerivations(accepted.Derivations, verified, now)
	if err != nil {
		return nil, err
	}
	credential.MergeDerived(doc, derived, accepted.Derivations)

	defaults, err := pScope.ResolveDefaults(now)
	if err != nil {
		return nil, err
	}
	// Presentation Defaults are documented as claim paths (dot-notation), so
	// use MergeDefaults to place e.g. "identity.country" under the nested
	// identity object rather than as a literal top-level key.
	if err := credential.MergeDefaults(doc, defaults); err != nil {
		return nil, err
	}

	credMeta := c.cfg.GetCredentialMetadata(scope)
	if credMeta == nil {
		return nil, fmt.Errorf("presentation scope %q has no credential_metadata entry; refusing to issue", scope)
	}
	if credMeta.Format == openid4vp.FormatMsoMdoc {
		return filterAgainstMDDL(doc, credMeta.GetMDDL())
	}
	// Snapshot VCTM through GetVCTM so a concurrent background refresh
	// (guarded by CredentialMetadata.mu) cannot swap the pointer between the
	// nil check and the filter.
	vctm := credMeta.GetVCTM()
	if vctm == nil {
		// Presentation-derived issuance without a declared claim allow-list
		// would leak every claim the presented credential carries (birthdate,
		// assurance_level, address, …) into the derived credential body.
		// Refuse issuance rather than emit an unfiltered document.
		return nil, fmt.Errorf("presentation scope %q has no VCTM to filter against; refusing to issue an unfiltered document", scope)
	}
	return credential.FilterAgainstVCTM(doc, vctm), nil
}

// filterAgainstMDDL keeps the elements the MDDL declares, keyed by element
// identifier as the mdoc signer reads them, with every full-date as
// "YYYY-MM-DD".
func filterAgainstMDDL(doc map[string]any, schema *mdoc.MDDLSchema) (map[string]any, error) {
	if schema == nil {
		return nil, errors.New("no MDDL to filter against; refusing to issue an unfiltered document")
	}
	out := map[string]any{}
	for _, claims := range schema.Claims {
		if err := copyDeclaredElements(out, doc, claims); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// copyDeclaredElements copies the elements of one MDDL namespace from doc
// into out.
func copyDeclaredElements(out, doc map[string]any, claims mdoc.NamespaceClaims) error {
	for element, meta := range claims {
		value, ok := doc[element]
		if !ok {
			continue
		}
		normalised, err := mddlValue(meta, value)
		if err != nil {
			return fmt.Errorf("element %q: %w", element, err)
		}
		out[element] = normalised
	}
	return nil
}

// mddlValue is value in the form the MDDL value type takes. A map or array
// keeps only the fields its declared Elements name.
func mddlValue(meta mdoc.ClaimMetadata, value any) (any, error) {
	switch {
	case meta.ValueType == "full-date":
		return normaliseFullDate(value)
	case len(meta.Elements) == 0:
		return value, nil
	case meta.ValueType == "map":
		fields, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected a map, got %T", value)
		}
		return declaredFields(meta.Elements, fields)
	case meta.ValueType == "array":
		items, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("expected an array, got %T", value)
		}
		out := make([]any, len(items))
		for i, item := range items {
			fields, ok := item.(map[string]any)
			if !ok {
				out[i] = item
				continue
			}
			filtered, err := declaredFields(meta.Elements, fields)
			if err != nil {
				return nil, fmt.Errorf("array item %d: %w", i, err)
			}
			out[i] = filtered
		}
		return out, nil
	}
	return value, nil
}

// declaredFields copies the fields of m that elements declares.
func declaredFields(elements map[string]mdoc.ClaimMetadata, m map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(elements))
	for name, meta := range elements {
		value, ok := m[name]
		if !ok {
			continue
		}
		filtered, err := mddlValue(meta, value)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
		out[name] = filtered
	}
	return out, nil
}
