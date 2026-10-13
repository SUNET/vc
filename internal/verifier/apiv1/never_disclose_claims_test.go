package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/cache"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The second filter, at the point claims leave for a frontend.
//
// It is a separate mechanism from the query filter on purpose: that one
// stops this verifier asking, this one stops anything that arrives
// regardless - volunteered by a wallet, or carried as an ordinary
// disclosed claim - from reaching a screen or a relying party. A single
// filter would mean a single place to get wrong.
func TestGetCredentialDisplayData_DoesNotReturnNeverDiscloseClaims(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	// A session whose verified claims carry a never-disclose attribute,
	// as they would if a wallet volunteered it or the credential carried
	// it as an ordinary disclosed claim.
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID: "display-session",
		VPToken:   "a-token",
		VerifiedClaims: map[string]any{
			"given_name": "Anna",
			"ssc":        "d424c7061fc1",
			"nested": map[string]any{
				"family_name": "Andersson",
				"psc":         "deadbeef",
			},
		},
	}))

	// The real handler, because it is the handler that has to do this -
	// composing the filter and the flattener in a test would prove the
	// two work together and say nothing about whether anything calls them.
	reply, err := client.GetCredentialDisplayData(ctx, &GetCredentialDisplayDataRequest{
		SessionID: "display-session",
	})
	require.NoError(t, err)
	require.NotNil(t, reply)

	assert.Contains(t, reply.Claims, "given_name")
	for key, value := range reply.Claims {
		assert.NotContains(t, key, "ssc", "a never-disclose claim must not reach a frontend")
		assert.NotContains(t, key, "psc")
		assert.NotEqual(t, "d424c7061fc1", value)
		assert.NotEqual(t, "deadbeef", value)
	}
}

// The filter runs before the claims are stored, so everything downstream
// reads an already-filtered set rather than each having to remember.
// Asserted on the stored context, which is what the OIDC claims, the
// result API and the display path all read.
func TestVerifiedClaimsAreFilteredBeforeTheyAreStored(t *testing.T) {
	client := newSigningTestClient(t)

	raw := map[string]any{"given_name": "Anna", "ssc": "d424c7061fc1"}
	filtered := client.cfg.NeverDisclose().FilterClaims(raw)

	require.Contains(t, filtered, "given_name")
	require.NotContains(t, filtered, "ssc")
	require.Contains(t, raw, "ssc", "filtering must not empty the caller's map")
}
