package apiv1

import (
	"errors"
	"fmt"
	"maps"
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

	doc := make(map[string]any, len(pScope.Defaults))

	derived, err := credential.ApplyDerivations(pScope.Derivations, authCtx.VerifiedClaims, now)
	if err != nil {
		return nil, err
	}
	maps.Copy(doc, derived)

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
	if credMeta == nil || credMeta.VCTM == nil {
		// Presentation-derived issuance without a declared claim allow-list
		// would leak every claim the presented credential carries (birthdate,
		// assurance_level, address, …) into the derived credential body.
		// Refuse issuance rather than emit an unfiltered document.
		return nil, fmt.Errorf("presentation scope %q has no VCTM to filter against; refusing to issue an unfiltered document", scope)
	}
	return credential.FilterAgainstVCTM(doc, credMeta.VCTM), nil
}
