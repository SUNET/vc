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
		}), log))
	})

	t.Run("a context that does not define the term", func(t *testing.T) {
		// The structural check cannot see this: a context IS configured.
		err := resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialContexts:   []string{unrelated},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}), log)
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
		}), log)
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
		}), log))
	})

	t.Run("an unreachable context fails at startup, not at issuance", func(t *testing.T) {
		err := resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format:             openid4vp.FormatLdpVCDCQL,
			CredentialTypes:    []string{"DiplomaCredential"},
			CredentialContexts: []string{"https://no-such-host.invalid/ctx.jsonld"},
		}), log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be loaded")
	})

	t.Run("scopes configuring no context are untouched", func(t *testing.T) {
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatLdpVCDCQL,
		}), log))
		assert.NoError(t, resolveW3CContexts(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatSDJWTVC,
		}), log))
	})
}
