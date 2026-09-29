package apiv1

import (
	"context"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
)

// finalisePresentationVerification stores the required claims from a
// presented credential onto authCtx.VerifiedClaims and validates the
// scope's per-claim allow-lists. The datastore lookup step is intentionally
// skipped: presentation-source credentials derive their whole document from
// the presented credential's own claims (see handlers_issuer.go's
// VCICredential presentation branch). A preview document is cached so the
// consent/preview UI (which calls UserLookup unconditionally) can render
// the credential-to-be-issued before final consent.
func (c *Client) finalisePresentationVerification(ctx context.Context, authCtx *cache.AuthorizationContext, pScope model.PresentationScope, presented map[string]any) error {
	// VPTokenValidator.validateAgainstDCQL is currently a no-op, so a
	// wallet could return a credential of the wrong type that happens to
	// carry the required claim keys. Enforce the presented type against
	// pScope.FromScope before minting anything from it.
	if err := c.enforceFromScopeType(pScope, presented); err != nil {
		return err
	}

	verified := make(map[string]any, len(pScope.RequiredClaims))
	for claim, allowed := range pScope.RequiredClaims {
		val, present := lookupClaimPath(presented, claim)
		if !present {
			return helpers.NewErrorDetailsWithStatus("missing_required_claim",
				fmt.Sprintf("claim %q not present on presented credential", claim),
				400)
		}
		if len(allowed) > 0 && !claimValueMatches(val, allowed) {
			return helpers.NewErrorDetailsWithStatus("claim_value_not_allowed",
				fmt.Sprintf("claim %q value not in allow-list", claim),
				403)
		}
		// Materialise dotted claim paths as nested map structures so the
		// downstream VCTM filter (which walks nested maps) can see them
		// under the same shape the presented credential used.
		setClaimPath(verified, claim, val)
	}
	authCtx.VerifiedClaims = verified
	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		return fmt.Errorf("failed to persist verified claims: %w", err)
	}

	// Cache a preview document keyed by session so UserLookup (called by the
	// consent flow before VCICredential runs) has something to render. The
	// authoritative document is rebuilt from VerifiedClaims in VCICredential.
	previewDoc := &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: pScope.FromScope,
		},
		DocumentData: verified,
	}
	c.cacheService.Document.Set(ctx, authCtx.SessionID, map[string]*model.CompleteDocument{
		pScope.FromScope: previewDoc,
	})
	return nil
}

// lookupClaimPath resolves a dot-delimited claim path against a nested claims
// map (e.g. "address.locality"). Returns the value and true when the path
// resolves fully; false when any intermediate segment is missing or is not
// a map.
func lookupClaimPath(claims map[string]any, path string) (any, bool) {
	if !strings.Contains(path, ".") {
		v, ok := claims[path]
		return v, ok
	}
	segments := strings.Split(path, ".")
	var cur any = claims
	for _, seg := range segments {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, present := m[seg]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// setClaimPath writes val at a dot-delimited path in dst, creating
// intermediate maps as needed. Existing intermediate maps are reused so
// multiple required claims sharing a prefix (e.g. "identity.given_name" and
// "identity.family_name") produce a single nested object rather than
// overwriting siblings.
func setClaimPath(dst map[string]any, path string, val any) {
	if !strings.Contains(path, ".") {
		dst[path] = val
		return
	}
	segments := strings.Split(path, ".")
	cur := dst
	for _, seg := range segments[:len(segments)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segments[len(segments)-1]] = val
}

// enforceFromScopeType refuses a presented credential whose type does not
// match pScope.FromScope. For SD-JWT VC the top-level `vct` claim carries
// the canonical type identifier and is compared against the configured
// credential metadata's vct. For other formats (e.g. mso_mdoc) the DCQL
// query slot's meta constraint is the trust anchor, and a stronger check
// belongs in VPTokenValidator.validateAgainstDCQL — refuse here rather
// than accept an unverifiable presentation.
func (c *Client) enforceFromScopeType(pScope model.PresentationScope, presented map[string]any) error {
	fromMeta := c.cfg.GetCredentialMetadata(pScope.FromScope)
	if fromMeta == nil {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("from_scope %q has no credential_metadata entry", pScope.FromScope),
			500)
	}
	vctRaw, ok := presented["vct"]
	if !ok {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			fmt.Sprintf("presented credential carries no vct; cannot enforce from_scope %q", pScope.FromScope),
			400)
	}
	vct, ok := vctRaw.(string)
	if !ok || vct == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			"presented credential vct is not a non-empty string",
			400)
	}
	expected := ""
	if vctm := fromMeta.GetVCTM(); vctm != nil {
		expected = vctm.VCT
	}
	if expected == "" {
		expected = fromMeta.GetVCTURL()
	}
	if expected == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("from_scope %q has no canonical vct", pScope.FromScope),
			500)
	}
	if vct != expected {
		return helpers.NewErrorDetailsWithStatus("presentation_type_mismatch",
			fmt.Sprintf("presented credential vct %q does not match from_scope %q (expected %q)", vct, pScope.FromScope, expected),
			403)
	}
	return nil
}

// claimValueMatches returns true if val (a scalar string or a list of them)
// contains at least one entry that appears in the allow-list.
func claimValueMatches(val any, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	switch v := val.(type) {
	case string:
		_, ok := allowedSet[v]
		return ok
	case []string:
		for _, s := range v {
			if _, ok := allowedSet[s]; ok {
				return true
			}
		}
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				continue
			}
			if _, ok := allowedSet[s]; ok {
				return true
			}
		}
	}
	return false
}
