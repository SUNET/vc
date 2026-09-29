package apiv1

import (
	"context"
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
)

// finalisePresentationVerification stores the required claims from a
// presented credential onto authCtx.VerifiedClaims and validates the
// scope's per-claim allow-lists. The datastore lookup + document
// cache-by-identity steps are intentionally skipped: presentation-source
// credentials derive their whole document from the presented credential's
// own claims (see handlers_issuer.go's VCICredential presentation branch).
func (c *Client) finalisePresentationVerification(ctx context.Context, authCtx *cache.AuthorizationContext, pScope model.PresentationScope, presented map[string]any) error {
	verified := make(map[string]any, len(pScope.RequiredClaims))
	for claim, allowed := range pScope.RequiredClaims {
		val, present := presented[claim]
		if !present {
			return &openid4vpGateError{code: 400, msg: fmt.Sprintf("missing required claim %q on presented credential", claim)}
		}
		if len(allowed) > 0 && !claimValueMatches(val, allowed) {
			return &openid4vpGateError{code: 403, msg: fmt.Sprintf("claim %q value not in allow-list", claim)}
		}
		verified[claim] = val
	}
	authCtx.VerifiedClaims = verified
	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		return fmt.Errorf("failed to persist verified claims: %w", err)
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

// openid4vpGateError carries an HTTP status hint through the handler chain
// for missing / disallowed claims discovered during the presentation-source
// verification finalisation step.
type openid4vpGateError struct {
	code int
	msg  string
}

func (e *openid4vpGateError) Error() string   { return e.msg }
func (e *openid4vpGateError) StatusCode() int { return e.code }
func (e *openid4vpGateError) Is(target error) bool {
	_, ok := target.(*openid4vpGateError)
	return ok || errors.Is(target, errPresentationGateSentinel)
}

var errPresentationGateSentinel = errors.New("presentation gate")
