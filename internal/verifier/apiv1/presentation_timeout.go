package apiv1

import (
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
