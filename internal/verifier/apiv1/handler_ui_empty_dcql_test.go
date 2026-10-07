package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
)

// A DCQL with an EMPTY credentials list asks for nothing, and
// validate:"required" does not catch it: the tag is on the pointer, which
// is non-nil. The per-credential validation loop then iterates zero
// credentials and finds nothing wrong.
//
// What makes it more than untidy is that the session is persisted with no
// scopes, so every later "was this answered?" check is driven by an empty
// list and passes vacuously. verifyVC20ForOIDC walks the session's
// credential scopes, finds none, and reports success - so an SD-JWT-only
// response is accepted and its claims mapped, against a request that asked
// for nothing at all.
func TestUIInteraction_RefusesADCQLThatAsksForNothing(t *testing.T) {
	client := newSigningTestClient(t)

	_, err := client.UIInteraction(t.Context(), &UIInteractionRequest{
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{}},
	})
	require.Error(t, err, "a request for no credential is not a request")
	require.Contains(t, err.Error(), "at least one credential")

	// And the control: the same handler must still accept a real query, or
	// the test above would pass against a handler that refuses everything.
	_, err = client.UIInteraction(t.Context(), &UIInteractionRequest{
		DCQLQuery: createTestDCQLForVP(t),
	})
	require.NoError(t, err)
}

// The response-side half, for sessions already persisted before the guard
// above existed. refuseAResponseThisPathCannotCheck is driven by the
// session's credential scopes, so an empty query made each of its checks
// vacuous rather than failing any of them.
func TestVerifyVC20ForOIDC_RefusesASessionThatAskedForNothing(t *testing.T) {
	client := newSigningTestClient(t)

	session := &cache.AuthorizationContext{
		SessionID: "empty-dcql-session",
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{}},
	}

	// An SD-JWT-only response: no W3C document, so every W3C-specific
	// check has nothing to look at and the old code returned success.
	err := client.verifyVC20ForOIDC(t.Context(), session, "eyJhbGciOiJFUzI1NiJ9.e30.sig~")
	require.Error(t, err, "a session that requested nothing cannot be answered")
	require.Contains(t, err.Error(), "asks for no credential")
}
