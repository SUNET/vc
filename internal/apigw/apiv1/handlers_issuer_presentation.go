package apiv1

import (
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/model"
)

// buildPresentationDocument assembles document_data for a credential whose
// data source is presentation. Reads the presented credential's claims from
// authCtx.VerifiedClaims (populated by finalisePresentationVerification),
// runs the scope's configured derivations via credential.ApplyDerivations,
// merges defaults, then filters against the target credential's VCTM so no
// non-declared PII survives into the derived credential.
func (c *Client) buildPresentationDocument(scope string, pScope model.PresentationScope, authCtx *cache.AuthorizationContext, now time.Time) (map[string]any, error) {
	if authCtx.VerifiedClaims == nil {
		return nil, errors.New("no verified presentation claims available for issuance")
	}

	// Start from a deep copy of the verified presentation claims so a VCTM
	// claim that the presented credential already carries (and that no
	// derivation rewrites) still lands in the issued document. The VCTM
	// filter below drops anything the target credential does not declare.
	doc := credential.CloneNestedClaims(authCtx.VerifiedClaims)

	derived, err := credential.ApplyDerivations(pScope.Derivations, authCtx.VerifiedClaims, now)
	if err != nil {
		return nil, err
	}
	credential.MergeNestedClaims(doc, derived)

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
