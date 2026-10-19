package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/require"
)

// A PDP plus this deployment's own registry is the one combination the
// status-list trust narrowing cannot serve: the registry signs its tokens
// with no kid, jwk or x5c, so JWTTrustVerifier has nothing to resolve and
// the PDP is never consulted, and resolveStatusListKey then refuses the
// generic resolver. Every local status check fails, and
// verifier.revocation.fail_open defaults to TRUE - so each failure reads as
// "not revoked" and a revoked credential is accepted, permanently, with
// only a per-request log line.
//
// Config load is where that has to surface, and specifically BEFORE
// LoadConfig prunes the sections this service does not own: it sets
// cfg.Registry = nil for the verifier, so a check any later cannot see the
// registry at all. The first version of this check ran in
// verifier/apiv1.New and was dead code for exactly that reason.
func TestCheckStatusListTrustPin(t *testing.T) {
	withRegistry := func(rev *model.RevocationConfig) *model.Cfg {
		return &model.Cfg{
			Registry: &model.Registry{PublicURL: "https://registry.example.com"},
			Verifier: &model.Verifier{
				Trust:      model.TrustConfig{PDPURL: "https://pdp.example.com"},
				Revocation: rev,
			},
		}
	}
	enabled := func(rev model.RevocationConfig) *model.RevocationConfig {
		rev.Enabled = true
		return &rev
	}

	t.Run("pinned to the registry is fine", func(t *testing.T) {
		require.NoError(t, checkStatusListTrustPin(withRegistry(enabled(model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/registry.pub.pem",
			StatusListIssuer:  "https://registry.example.com",
		})), "verifier"))
	})

	t.Run("no pin at all is refused", func(t *testing.T) {
		err := checkStatusListTrustPin(withRegistry(enabled(model.RevocationConfig{})), "verifier")
		require.Error(t, err)
		require.Contains(t, err.Error(), "https://registry.example.com",
			"the error must name the value status_list_issuer has to take")
	})

	// A key file alone does not do it. pinApplies only covers a token whose
	// iss is the configured status_list_issuer, and the registry's tokens
	// carry iss = registry.public_url - so a pin aimed at an external
	// service leaves the registry's own lists unverifiable.
	t.Run("a pin aimed elsewhere is refused", func(t *testing.T) {
		err := checkStatusListTrustPin(withRegistry(enabled(model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/external.pub.pem",
			StatusListIssuer:  "https://status.example.org",
		})), "verifier")
		require.Error(t, err)
	})

	t.Run("a key file with no issuer is refused", func(t *testing.T) {
		err := checkStatusListTrustPin(withRegistry(enabled(model.RevocationConfig{
			StatusListKeyFile: "/etc/vc/registry.pub.pem",
		})), "verifier")
		require.Error(t, err)
	})

	// The configurations that have nothing to fix.
	t.Run("revocation disabled is unaffected", func(t *testing.T) {
		require.NoError(t, checkStatusListTrustPin(withRegistry(&model.RevocationConfig{}), "verifier"))
	})

	t.Run("no local registry is unaffected", func(t *testing.T) {
		require.NoError(t, checkStatusListTrustPin(&model.Cfg{
			Verifier: &model.Verifier{
				Trust:      model.TrustConfig{PDPURL: "https://pdp.example.com"},
				Revocation: enabled(model.RevocationConfig{}),
			},
		}, "verifier"))
	})

	t.Run("no PDP is unaffected", func(t *testing.T) {
		require.NoError(t, checkStatusListTrustPin(&model.Cfg{
			Registry: &model.Registry{PublicURL: "https://registry.example.com"},
			Verifier: &model.Verifier{Revocation: enabled(model.RevocationConfig{})},
		}, "verifier"))
	})

	// Another service loading the same shared file is not this check's
	// business - it is the verifier that would fail to verify.
	t.Run("another service is unaffected", func(t *testing.T) {
		require.NoError(t, checkStatusListTrustPin(withRegistry(enabled(model.RevocationConfig{})), "issuer"))
	})
}

// TestCheckStatusListTrustPin_MustRunBeforePruning pins the ORDER, which is
// the part that actually went wrong.
//
// The check itself was written and tested and correct, and ran in
// verifier/apiv1.New - where cfg.Registry has already been set to nil for
// the verifier service, so it returned early every single time. A unit test
// of the predicate cannot see that; this one can.
func TestCheckStatusListTrustPin_MustRunBeforePruning(t *testing.T) {
	shared := func() *model.Cfg {
		return &model.Cfg{
			Registry: &model.Registry{PublicURL: "https://registry.example.com"},
			Verifier: &model.Verifier{
				Trust:      model.TrustConfig{PDPURL: "https://pdp.example.com"},
				Revocation: &model.RevocationConfig{Enabled: true},
			},
		}
	}

	require.Error(t, checkStatusListTrustPin(shared(), "verifier"),
		"before pruning the registry is visible and the misconfiguration is caught")

	pruned := shared()
	pruneForeignSections(pruned, "verifier")
	require.Nil(t, pruned.Registry, "the verifier does not own the registry stanza")
	require.NoError(t, checkStatusListTrustPin(pruned, "verifier"),
		"after pruning the same check cannot see anything - which is exactly how it was dead code")
}

// TestNew_RefusesAPDPVerifierWithAnUnpinnedRegistry drives the real loader,
// because the predicate tests above cannot see WHERE it is called - and
// where it is called is the thing that was wrong. The first version ran in
// verifier/apiv1.New, after cfg.Registry had already been nil'd, and every
// unit test of it still passed.
func TestNew_RefusesAPDPVerifierWithAnUnpinnedRegistry(t *testing.T) {
	dir := t.TempDir()
	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{"vct":"urn:eudi:pid:1"}`), 0o600))

	write := func(t *testing.T, revocation string) string {
		t.Helper()
		path := filepath.Join(dir, "config-"+t.Name()+".yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    pid:
      format: dc+sd-jwt
      vctm_file_path: `+vctm+`
registry:
  public_url: https://registry.example.com
verifier:
  trust:
    pdp_url: https://pdp.example.com
  revocation:
    enabled: true
`+revocation+`
`), 0o600))
		return path
	}

	t.Run("unpinned is refused", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, ""))
		_, err := New(t.Context(), "verifier")
		require.Error(t, err)
		require.Contains(t, err.Error(), "https://registry.example.com",
			"the error must name the value status_list_issuer has to take")
	})

	// The control. Without it the case above would pass on any loader
	// failure at all - a missing field, a bad path, anything.
	//
	// This config is still incomplete for a real verifier (public_url,
	// key_config and inbound.openid4vp are all required), so it does fail -
	// but it gets PAST the pin check to the schema validation that comes
	// after it, which is the thing being proven. Building a fully valid
	// verifier stanza here would test the schema, not the ordering.
	t.Run("pinned to the registry gets past this check", func(t *testing.T) {
		key := filepath.Join(dir, "registry.pub.pem")
		require.NoError(t, os.WriteFile(key, []byte("-- not parsed at load time --"), 0o600))
		t.Setenv("VC_CONFIG_YAML", write(t,
			"    status_list_issuer: https://registry.example.com\n"+
				"    status_list_key_file: "+key))
		_, err := New(t.Context(), "verifier")
		require.Error(t, err)
		require.NotContains(t, err.Error(), "do not pin that registry",
			"a pinned registry must not be refused by the pin check")
		require.Contains(t, err.Error(), "validation_error",
			"it fails later, on the schema - which is how we know the pin check let it through")
	})
}
