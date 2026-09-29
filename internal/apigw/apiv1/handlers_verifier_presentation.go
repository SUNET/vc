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
	verified := make(map[string]any, len(pScope.RequiredClaims))
	for claim, allowed := range pScope.RequiredClaims {
		val, present := lookupClaimPath(presented, claim)
		if !present {
			return helpers.NewErrorDetails("missing_required_claim",
				fmt.Sprintf("claim %q not present on presented credential", claim))
		}
		if len(allowed) > 0 && !claimValueMatches(val, allowed) {
			return helpers.NewErrorDetails("claim_value_not_allowed",
				fmt.Sprintf("claim %q value not in allow-list", claim))
		}
		verified[claim] = val
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
