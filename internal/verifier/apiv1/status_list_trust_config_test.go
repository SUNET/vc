package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/require"
)

// TestStatusListTrustEvaluationEnabled: the trust verifier NARROWS how a
// status list token may be verified - one naming no key in its own header,
// or a CWT, then verifies against a pinned key or not at all.
//
// Without verifier.trust.pdp_url that narrowing buys nothing, because the
// evaluator is AllowAllEvaluator, and it costs everything: vc's own registry
// issues status list tokens with no kid, jwk or x5c, so a default
// registry-only deployment could no longer verify its own lists - and with
// revocation.fail_open at its default that reads as "not revoked".
func TestStatusListTrustEvaluationEnabled(t *testing.T) {
	withPDP := &model.Cfg{Verifier: &model.Verifier{Trust: model.TrustConfig{PDPURL: "https://pdp.example.com"}}}
	require.True(t, statusListTrustEvaluationEnabled(withPDP))

	require.False(t, statusListTrustEvaluationEnabled(&model.Cfg{Verifier: &model.Verifier{}}),
		"no PDP means no policy to consult, so nothing to narrow to")
	require.False(t, statusListTrustEvaluationEnabled(&model.Cfg{}))
	require.False(t, statusListTrustEvaluationEnabled(nil))
}
