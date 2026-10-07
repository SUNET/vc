package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
)

// TestValidateDCQL_RefusesAnEmptyCredentialList: validateDCQL iterates the
// credential queries, so an empty list ran the loop zero times and reported
// nothing wrong - and so did uncoveredScopes and unclaimedRequiredQueries,
// which iterate the same empty list.
//
// A matched presentation template with no credential queries therefore
// produced a request asking for nothing, which went out signed to the
// wallet; the direct-post guards then refused the response. That is the
// right outcome discovered at the worst moment - after the user has been
// sent to their wallet and come back.
//
// UIInteraction already refuses an empty dcql_query. This is the other way
// a request is built.
func TestValidateDCQL_RefusesAnEmptyCredentialList(t *testing.T) {
	err := validateDCQL(&openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{}})
	require.Error(t, err, "a request for no credential is not a request")
	require.Contains(t, err.Error(), "no credential")

	// A nil query is NOT this function's business: the caller decides
	// whether one was required, and callers legitimately pass nil.
	require.NoError(t, validateDCQL(nil))

	// The control: a real query still passes, or the assertion above would
	// hold against a validator that refused everything.
	require.NoError(t, validateDCQL(&openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID:     "pid",
		Format: "mso_mdoc",
		Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.pid.1"},
	}}}))
}
