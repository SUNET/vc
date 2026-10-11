package apiv1

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/cache"
)

// sessionExpired reports whether this authorization context is past its
// presentation deadline.
//
// Zero means no deadline, which is how contexts were created before
// presentation_timeout was read; such a context is bounded only by cache
// eviction.
func sessionExpired(authCtx *cache.AuthorizationContext) bool {
	if authCtx == nil || authCtx.ExpiresAt == 0 {
		return false
	}
	// >=, not >: isReusableAuthContext treats ExpiresAt <= now as expired,
	// and with timestamps truncated to seconds a > here left direct-post
	// accepted for the whole boundary second while the UI had already given
	// up on the session.
	return time.Now().Unix() >= authCtx.ExpiresAt
}

// authContextFor resolves the authorization context a request object
// belongs to, or nil when there is none to resolve.
//
// Two lookups because the two flows key it differently: the standalone UI
// flow sets the request object's State to the context's State, while the
// OIDC flow sets it to the session id. Nil rather than an error - the
// caller only asks in order to apply a deadline, and a context that cannot
// be found carries no deadline to apply.
func (c *Client) authContextFor(ctx context.Context, state string) *cache.AuthorizationContext {
	if state == "" {
		return nil
	}
	if authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: state}); err == nil && authCtx != nil {
		return authCtx
	}
	if authCtx, err := c.cacheService.AuthContext.GetByID(ctx, state); err == nil {
		return authCtx
	}
	return nil
}

// authSessionIsTerminal reports whether this authorization context has
// already reached an outcome, by EITHER of the two markers the flows use.
//
// Status is the OIDC OP's: handler_oidc.go writes it at each step. The
// standalone UI flow does not - VerificationDirectPost records completion
// by setting VerifierResponseCode and leaves Status empty - so a check on
// Status alone classifies a finished standalone session as unfinished,
// and once its deadline passes, as expired. That matters because the tab
// is still waiting to reconcile the response code it never received.
func authSessionIsTerminal(authCtx *cache.AuthorizationContext) bool {
	if authCtx == nil {
		return false
	}
	return sessionStatusIsTerminal(authCtx.Status) || authCtx.VerifierResponseCode != ""
}

// sessionStatusIsTerminal reports whether a session has already reached an
// outcome, so a deadline passing afterwards changes nothing about it.
func sessionStatusIsTerminal(status cache.SessionStatus) bool {
	switch status {
	case cache.SessionStatusCodeIssued, cache.SessionStatusTokenIssued,
		cache.SessionStatusCompleted, cache.SessionStatusError,
		cache.SessionStatusExpired:
		return true
	}
	return false
}
