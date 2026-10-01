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

// A PDP plus this deployment's own registry is the one combination the
// narrowing cannot serve: the registry signs its status list tokens with no
// kid, jwk or x5c, so JWTTrustVerifier has nothing to resolve and the PDP
// is never consulted, and resolveStatusListKey then refuses the generic
// resolver. Every local status check fails, and revocation.fail_open
// defaults to TRUE - so each failure reads as "not revoked" and a revoked
// credential is accepted, permanently, with only a per-request log line.
//
// Startup is where that has to surface.
func TestRequireLocalRegistryStatusListPin(t *testing.T) {
	withRegistry := func(rev *model.RevocationConfig) *model.Cfg {
		return &model.Cfg{
			Registry: &model.Registry{PublicURL: "https://registry.example.com"},
			Verifier: &model.Verifier{
				Trust:      model.TrustConfig{PDPURL: "https://pdp.example.com"},
				Revocation: rev,
			},
		}
	}

	t.Run("pinned to the registry is fine", func(t *testing.T) {
		require.NoError(t, requireLocalRegistryStatusListPin(withRegistry(&model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/registry.pub.pem",
			StatusListIssuer:  "https://registry.example.com",
		})))
	})

	t.Run("no pin at all is refused", func(t *testing.T) {
		err := requireLocalRegistryStatusListPin(withRegistry(&model.RevocationConfig{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "https://registry.example.com",
			"the error must name the value status_list_issuer has to take")
	})

	// A key file alone does not do it. pinApplies only covers a token whose
	// iss is the configured status_list_issuer, and the registry's tokens
	// carry iss = registry.public_url - so a pin aimed at an external
	// service leaves the registry's own lists unverifiable.
	t.Run("a pin aimed elsewhere is refused", func(t *testing.T) {
		err := requireLocalRegistryStatusListPin(withRegistry(&model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/external.pub.pem",
			StatusListIssuer:  "https://status.example.org",
		}))
		require.Error(t, err)
	})

	t.Run("a key file with no issuer is refused", func(t *testing.T) {
		err := requireLocalRegistryStatusListPin(withRegistry(&model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/registry.pub.pem",
		}))
		require.Error(t, err)
	})

	// The two configurations that have nothing to fix. A standalone
	// verifier sees only external lists, which carry their signer in the
	// token and are judged by the PDP - that path needs no pin.
	t.Run("no local registry is unaffected", func(t *testing.T) {
		require.NoError(t, requireLocalRegistryStatusListPin(&model.Cfg{
			Verifier: &model.Verifier{
				Trust:      model.TrustConfig{PDPURL: "https://pdp.example.com"},
				Revocation: &model.RevocationConfig{},
			},
		}))
	})

	t.Run("no PDP is unaffected", func(t *testing.T) {
		require.NoError(t, requireLocalRegistryStatusListPin(&model.Cfg{
			Registry: &model.Registry{PublicURL: "https://registry.example.com"},
			Verifier: &model.Verifier{Revocation: &model.RevocationConfig{}},
		}))
	})
}
