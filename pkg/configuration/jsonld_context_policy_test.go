package configuration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cfgNaming builds a deployment whose one W3C scope names contextURL.
func cfgNaming(contextURL string) *model.Cfg {
	return &model.Cfg{Common: &model.Common{
		CredentialMetadata: map[string]*model.CredentialMetadata{"diploma": {
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{contextURL},
		}},
	}}
}

// takePinner hands back the Pinner the resolution just installed, and
// makes sure its background loop does not outlive the test.
func takePinner(t *testing.T) *credential.Pinner {
	t.Helper()
	pinner := credential.GlobalPinner()
	require.NotNil(t, pinner)
	t.Cleanup(func() {
		pinner.Stop()
		credential.SetGlobalPinner(nil)
	})
	return pinner
}

// The defaults are asymmetric on purpose, and that asymmetry is the whole
// point of the change: an issuer that cannot resolve a context cannot sign
// the credential either, while a verifier loses one credential type and
// should keep serving the rest rather than crash-loop.
func TestStartupPolicyDefaultsDifferByService(t *testing.T) {
	log := logger.NewSimple("test")
	const unresolvable = "https://ctx.invalid/policy-defaults.jsonld"

	t.Run("the issuer still refuses to start", func(t *testing.T) {
		err := resolveW3CContexts(context.Background(), cfgNaming(unresolvable), "issuer", log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be loaded")
		assert.Contains(t, err.Error(), "so credentials of this type cannot be signed")
	})

	t.Run("the verifier starts and reports itself not ready", func(t *testing.T) {
		require.NoError(t, resolveW3CContexts(context.Background(), cfgNaming(unresolvable), "verifier", log),
			"an unreachable context must not crash-loop a verifier")

		pinner := takePinner(t)
		err := pinner.HealthProbe(context.Background())
		require.Error(t, err, "it is running but cannot canonicalize this credential type")
		assert.Contains(t, err.Error(), unresolvable)
		assert.Equal(t, []string{unresolvable}, pinner.Pending())
	})
}

// The failure text has to describe THIS service. Telling a verifier
// operator that credentials "cannot be signed" sends them to a service that
// is not running and a key that is not involved.
func TestFailureTextDescribesTheServiceItBroke(t *testing.T) {
	log := logger.NewSimple("test")
	const unresolvable = "https://ctx.invalid/consequence.jsonld"

	cfg := cfgNaming(unresolvable)
	cfg.Common.JSONLDContexts.StartupPolicy = model.JSONLDContextRequired

	err := resolveW3CContexts(context.Background(), cfg, "verifier", log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "so presentations of this credential type cannot be verified")
	assert.NotContains(t, err.Error(), "cannot be signed")
}

// An operator can put the old behaviour back on the verifier, and can take
// it off the issuer. Neither default is a decision the code gets to keep.
func TestStartupPolicyIsConfigurablePerService(t *testing.T) {
	log := logger.NewSimple("test")
	const unresolvable = "https://ctx.invalid/per-service.jsonld"

	t.Run("a verifier can be made to require its contexts", func(t *testing.T) {
		cfg := cfgNaming(unresolvable)
		cfg.Common.JSONLDContexts.StartupPolicyPerService = map[string]model.JSONLDContextPolicy{
			"verifier": model.JSONLDContextRequired,
		}
		require.Error(t, resolveW3CContexts(context.Background(), cfg, "verifier", log))
	})

	t.Run("an issuer can be allowed to start without them", func(t *testing.T) {
		cfg := cfgNaming(unresolvable)
		cfg.Common.JSONLDContexts.StartupPolicyPerService = map[string]model.JSONLDContextPolicy{
			"issuer": model.JSONLDContextBestEffort,
		}
		require.NoError(t, resolveW3CContexts(context.Background(), cfg, "issuer", log))

		pinner := takePinner(t)
		assert.Error(t, pinner.HealthProbe(context.Background()),
			"an issuer that starts without a context it signs with is emphatically not ready")
	})

	t.Run("the per-service setting beats the global one", func(t *testing.T) {
		cfg := cfgNaming(unresolvable)
		cfg.Common.JSONLDContexts.StartupPolicy = model.JSONLDContextRequired
		cfg.Common.JSONLDContexts.StartupPolicyPerService = map[string]model.JSONLDContextPolicy{
			"verifier": model.JSONLDContextLazy,
		}
		require.NoError(t, resolveW3CContexts(context.Background(), cfg, "verifier", log))
	})
}

// Under "lazy" nothing is fetched and nothing gates readiness, which is
// what choosing it asks for - and is why it is opt-in.
func TestLazyPolicyStartsWithoutTouchingTheNetwork(t *testing.T) {
	log := logger.NewSimple("test")
	cfg := cfgNaming("https://ctx.invalid/lazy-policy.jsonld")
	cfg.Common.JSONLDContexts.StartupPolicy = model.JSONLDContextLazy

	require.NoError(t, resolveW3CContexts(context.Background(), cfg, "verifier", log))

	pinner := takePinner(t)
	assert.NoError(t, pinner.HealthProbe(context.Background()))
	assert.Empty(t, pinner.Pending())
}

// An operator's own copy of a context removes the startup network
// dependency entirely: the context that cannot be resolved is served from
// disk, and the deployment starts clean under the strictest policy.
func TestAConfiguredSourceRemovesTheNetworkDependency(t *testing.T) {
	log := logger.NewSimple("test")
	const unresolvable = "https://ctx.invalid/served-locally.jsonld"

	path := filepath.Join(t.TempDir(), "diploma.jsonld")
	require.NoError(t, os.WriteFile(path,
		[]byte(`{"@context":{"DiplomaCredential":"https://example.org/diploma#DiplomaCredential"}}`), 0o600))

	cfg := cfgNaming(unresolvable)
	cfg.Common.JSONLDContexts.StartupPolicy = model.JSONLDContextRequired
	cfg.Common.JSONLDContexts.Sources = map[string]model.JSONLDContextSource{
		unresolvable: {File: path},
	}

	require.NoError(t, resolveW3CContexts(context.Background(), cfg, "issuer", log),
		"nothing is dereferenced when the operator has supplied the document")

	pinner := takePinner(t)
	assert.NoError(t, pinner.HealthProbe(context.Background()))
}

// A source entry that cannot name a document is refused where it is
// written, for every service - including the ones that never resolve a
// context, because they share the file and a typo found at the next
// verifier restart is a typo found too late.
func TestJSONLDContextSourcesAreValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctx.jsonld")
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{}}`), 0o600))

	cfgWithSource := func(source model.JSONLDContextSource) *model.Cfg {
		return &model.Cfg{Common: &model.Common{
			JSONLDContexts: model.JSONLDContexts{
				Sources: map[string]model.JSONLDContextSource{"https://ctx.example.org/x.jsonld": source},
			},
		}}
	}

	for _, tc := range []struct {
		name   string
		source model.JSONLDContextSource
		want   string
	}{
		{"neither file nor url", model.JSONLDContextSource{}, "set either file or url"},
		{"both file and url", model.JSONLDContextSource{File: path, URL: "https://m.example.org/x"}, "set one"},
		{"a file that is not there", model.JSONLDContextSource{File: filepath.Join(t.TempDir(), "absent")}, "cannot be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkJSONLDContextSources(cfgWithSource(tc.source))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "common.jsonld_contexts.sources",
				"the failure has to name the setting the operator has to fix")
		})
	}

	t.Run("a readable file is accepted", func(t *testing.T) {
		assert.NoError(t, checkJSONLDContextSources(cfgWithSource(model.JSONLDContextSource{File: path})))
	})

	t.Run("a mirror url is accepted", func(t *testing.T) {
		assert.NoError(t, checkJSONLDContextSources(cfgWithSource(model.JSONLDContextSource{URL: "https://m.example.org/x"})))
	})

	t.Run("an apigw sees the same failure", func(t *testing.T) {
		// It resolves no contexts, so without this check the typo waits
		// for the next verifier restart to be noticed.
		err := w3cStartupChecks(context.Background(), cfgWithSource(model.JSONLDContextSource{}), "apigw", logger.NewSimple("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "set either file or url")
	})
}
