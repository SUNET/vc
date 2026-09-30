package configuration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveContext publishes a JSON-LD context and returns its URL. The loader
// refuses to dial loopback, so the document is pinned directly - what these
// tests exercise is the consistency checking, not the fetch.
func serveContext(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	credential.GetGlobalLoader().AddContext(srv.URL, body)
	return srv.URL
}

// TestResolveW3CContexts pins what resolution buys over the structural check:
// whether a context actually DEFINES each term, and whether the resulting IRIs
// are the ones the query asks for. Neither is answerable without expanding.
func TestResolveW3CContexts(t *testing.T) {
	log := logger.NewSimple("test")
	const diplomaIRI = "https://example.org/diploma#DiplomaCredential"

	defines := serveContext(t, `{"@context":{"DiplomaCredential":"`+diplomaIRI+`"}}`)
	unrelated := serveContext(t, `{"@context":{"SomethingElse":"https://example.org/other#SomethingElse"}}`)

	cfgWith := func(cm *model.CredentialMetadata) *model.Cfg {
		return &model.Cfg{Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{"diploma": cm},
		}}
	}

	t.Run("the context defines the term and the query matches it", func(t *testing.T) {
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialContexts:   []string{defines},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}), "issuer", log))
	})

	t.Run("a context that does not define the term", func(t *testing.T) {
		// The structural check cannot see this: a context IS configured.
		err := resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialContexts:   []string{unrelated},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}), "issuer", log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "defines none of")
	})

	t.Run("the term expands, but to an IRI the query does not ask for", func(t *testing.T) {
		err := resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{defines},
			// A different IRI than the context maps the term to.
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, "https://example.org/diploma#MastersCredential"}},
		}), "issuer", log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential_type_values alternative is satisfied")
	})

	t.Run("one satisfiable alternative among several is enough", func(t *testing.T) {
		// MatchTypeValues is satisfied by any one alternative, so the check
		// must be too.
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{defines},
			CredentialTypeValues: [][]string{
				{openid4vp.BaseVCTypeIRI, "https://example.org/diploma#MastersCredential"},
				{openid4vp.BaseVCTypeIRI, diplomaIRI},
			},
		}), "issuer", log))
	})

	t.Run("an unreachable context fails at startup, not at issuance", func(t *testing.T) {
		err := resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{"https://no-such-host.invalid/ctx.jsonld"},
		}), "issuer", log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be loaded")
	})

	t.Run("scopes configuring no context are untouched", func(t *testing.T) {
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatLdpVCDCQL,
		}), "issuer", log))
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatSDJWTVC,
		}), "issuer", log))
	})
}

// TestResolveW3CContextsPinsTheIssuerAllowlist: issuer.jsonld_context_allowlist
// names the URLs a MakeVC20 request may put in additional_contexts, and
// validateAdditionalContexts matches only the literal top-level URL. Nothing
// checked what that document then pulled in, so an allowlisted context could
// make the issuer fetch an unlisted public endpoint per request.
//
// Pinning the closure at startup is what answers that: the graph is fetched
// once, at boot, and the signing path then makes no outbound request at all.
// Transitivity itself is pinned by
// credential.TestPinRemoteContext_PinsReferencedContexts; what this covers is
// that config load actually reaches PinRemoteContext for allowlist entries.
func TestResolveW3CContextsPinsTheIssuerAllowlist(t *testing.T) {
	log := logger.NewSimple("test")

	loadable := serveContext(t, `{"@context":{"Extra":"https://example.org/extra#Extra"}}`)

	t.Run("an allowlisted context is loaded at startup", func(t *testing.T) {
		require.NoError(t, resolveW3CContexts(&model.Cfg{
			Issuer: &model.Issuer{JSONLDContextAllowlist: []string{loadable}},
		}, "issuer", log))
	})

	t.Run("one that cannot be loaded fails the boot", func(t *testing.T) {
		err := resolveW3CContexts(&model.Cfg{
			Issuer: &model.Issuer{JSONLDContextAllowlist: []string{"https://ctx.invalid/never-resolves.jsonld"}},
		}, "issuer", log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer.jsonld_context_allowlist",
			"the failure has to name the setting the operator has to fix")
	})

	// The verifier loads the same shared config file, and the switch that
	// nils out sibling stanzas has not run yet - so it was pinning every URL
	// in an allowlist it never consults, inheriting the issuer's startup
	// network dependency and failing to start when an issuer-only context
	// was unavailable. It serves no MakeVC20 request and dereferences
	// nothing from this list.
	t.Run("the verifier does not pin the issuer's allowlist", func(t *testing.T) {
		unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		t.Cleanup(unreachable.Close)

		cfg := &model.Cfg{Issuer: &model.Issuer{JSONLDContextAllowlist: []string{unreachable.URL}}}

		require.Error(t, resolveW3CContexts(cfg, "issuer", log),
			"the issuer does dereference this list, so an unloadable entry still fails its boot")
		assert.NoError(t, resolveW3CContexts(cfg, "verifier", log),
			"the verifier must not inherit a dependency it never uses")
	})

	t.Run("no allowlist is not an error", func(t *testing.T) {
		assert.NoError(t, resolveW3CContexts(&model.Cfg{Issuer: &model.Issuer{}}, "issuer", log))
		assert.NoError(t, resolveW3CContexts(&model.Cfg{}, "issuer", log))
	})
}

// TestCheckIssuerContextAllowlist: the apigw forwards a scope's
// credential_contexts verbatim as additional_contexts, and the issuer's
// validateAdditionalContexts matches those literally against
// issuer.jsonld_context_allowlist. A scope whose context is absent from the
// allowlist therefore started cleanly and failed EVERY issuance of that
// credential, after the user had already reached their wallet.
func TestCheckIssuerContextAllowlist(t *testing.T) {
	const contextURL = "https://example.org/diploma"

	w3cScope := func() map[string]*model.CredentialMetadata {
		return map[string]*model.CredentialMetadata{"diploma": {
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{contextURL},
		}}
	}

	t.Run("a context the allowlist names is fine", func(t *testing.T) {
		assert.NoError(t, checkIssuerContextAllowlist(&model.Cfg{
			Common: &model.Common{CredentialMetadata: w3cScope()},
			Issuer: &model.Issuer{JSONLDContextAllowlist: []string{contextURL}},
		}))
	})

	t.Run("a context the allowlist omits is refused at startup", func(t *testing.T) {
		err := checkIssuerContextAllowlist(&model.Cfg{
			Common: &model.Common{CredentialMetadata: w3cScope()},
			Issuer: &model.Issuer{JSONLDContextAllowlist: []string{"https://example.org/something-else"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jsonld_context_allowlist")
		assert.Contains(t, err.Error(), contextURL)
	})

	t.Run("an empty allowlist with a W3C scope is refused too", func(t *testing.T) {
		require.Error(t, checkIssuerContextAllowlist(&model.Cfg{
			Common: &model.Common{CredentialMetadata: w3cScope()},
			Issuer: &model.Issuer{},
		}))
	})

	t.Run("a non-W3C scope is not this check's business", func(t *testing.T) {
		assert.NoError(t, checkIssuerContextAllowlist(&model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"pid": {
				Format:             openid4vp.FormatSDJWTVC,
				CredentialContexts: []string{contextURL},
			}}},
			Issuer: &model.Issuer{},
		}))
	})

	// The verifier and the apigw load the same shared config file, neither
	// enforces this allowlist, and the apigw has no Issuer stanza of its own
	// by the time it is checked. Failing them here would refuse a valid
	// deployment, so the check is gated on the service and on the stanza.
	t.Run("a config with no issuer stanza is not checked", func(t *testing.T) {
		assert.NoError(t, checkIssuerContextAllowlist(&model.Cfg{
			Common: &model.Common{CredentialMetadata: w3cScope()},
		}))
	})
}

// TestW3CStartupChecksEnforceTheAllowlistBeforeFetching: the allowlist is an
// outbound-fetch boundary. Running resolveW3CContexts first contacted every
// configured context - including one the operator had deliberately left out
// of the allowlist - and only then refused it, by which time the request had
// been made.
//
// The order is only observable through a context that CANNOT be resolved: an
// unregistered loopback URL, which the loader refuses to dial. Run
// allowlist-first and the error names the allowlist; run resolution first
// and it names the failed load. A resolvable context would produce the same
// message either way, which is how the first version of this test passed
// against the very ordering it was written to catch.
func TestW3CStartupChecksEnforceTheAllowlistBeforeFetching(t *testing.T) {
	log := logger.NewSimple("test")
	const diplomaIRI = "https://example.org/diploma#DiplomaCredential"

	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = w.Write([]byte(`{"@context":{"DiplomaCredential":"` + diplomaIRI + `"}}`))
	}))
	t.Cleanup(unreachable.Close)

	cfgWithAllowlist := func(allowlist []string) *model.Cfg {
		return &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"diploma": {
				Format:               openid4vp.FormatLdpVCDCQL,
				CredentialTypes:      []string{"DiplomaCredential"},
				CredentialContexts:   []string{unreachable.URL},
				CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
			}}},
			Issuer: &model.Issuer{JSONLDContextAllowlist: allowlist},
		}
	}

	err := w3cStartupChecks(cfgWithAllowlist(nil), "issuer", log)
	require.Error(t, err, "an issuer whose scope names a context its allowlist does not must not start")
	assert.Contains(t, err.Error(), "jsonld_context_allowlist",
		"the allowlist must refuse it before anything dereferences the context")
	assert.NotContains(t, err.Error(), "could not be loaded",
		"reaching the context at all is the failure - naming it afterwards is too late")

	// Allowlisted, the same context is dereferenced and the fetch is what
	// fails. That is the contrast that makes the assertion above mean
	// something: both gates are live, and only their order decides.
	err = w3cStartupChecks(cfgWithAllowlist([]string{unreachable.URL}), "issuer", log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not be loaded")

	// The verifier loads the same shared file and enforces no allowlist, so
	// the allowlist must not speak for it: it gets as far as the fetch.
	err = w3cStartupChecks(cfgWithAllowlist(nil), "verifier", log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not be loaded")
}
