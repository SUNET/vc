package httpserver

import (
	"bytes"
	"html/template"
	"testing"

	"github.com/SUNET/vc/internal/apigw/staticembed"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// parseConsentTemplate mirrors exactly how Service.Default builds the HTML
// template set (same template.New("").Funcs(...).ParseFS(staticembed.FS,
// "*.html") call in service.go), so this test exercises the real template
// as rendered in production, not a stand-in.
func parseConsentTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"json": func(v any) (any, error) { return template.JS(""), nil }, //#nosec G203 -- unused by consent.html, present only to mirror service.go's FuncMap
	})
	return template.Must(tmpl.ParseFS(staticembed.FS, "*.html"))
}

// TestConsentTemplate_PreservesCustomSchemeRedirectURL locks in the fix for
// a live-testing finding (EUDI reference wallet, PLAN.md workstream 7):
// html/template's URL-attribute escaper only trusts a small scheme
// allowlist (http/https/mailto), so a custom-scheme redirect_uri like the
// wallet's own "eu.europa.ec.euidi://authorization" -- passed as a plain
// string -- gets silently replaced with the "#ZgotmplZ" safety sentinel
// instead of erroring, breaking consent.js's redirect. Wrapping it as
// template.URL(...) (endpoints_oauth.go) bypasses that scheme check.
//
// endpoints_oauth.go's own safety argument for doing this is that
// redirectURL is always server-derived -- from a registered client's own
// redirect_uri (validated against that client's allowlist at PAR time,
// handlers_oauth.go's OAuthPar) or an internal SAML/OIDC auth-provider
// redirect -- never raw user input. This test doesn't re-verify that
// upstream validation (that's handlers_oauth_test.go's job); it locks down
// the narrower, easily-regressed invariant that *this* rendering step
// keeps behaving correctly for such a URL, so a future edit that
// accidentally reverts template.URL(...) to a plain string is caught here
// rather than only in a live wallet retest.
func TestConsentTemplate_PreservesCustomSchemeRedirectURL(t *testing.T) {
	tmpl := parseConsentTemplate(t)
	const customSchemeURL = "eu.europa.ec.euidi://authorization?client_id=test"

	t.Run("template.URL preserves a custom-scheme redirect URL", func(t *testing.T) {
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, "consent.html", gin.H{
			"AuthMethod":  "openid4vp",
			"RedirectURL": template.URL(customSchemeURL),
		})
		require.NoError(t, err)
		require.Contains(t, buf.String(), customSchemeURL, "custom-scheme redirect URL must render unmodified when wrapped in template.URL")
		require.NotContains(t, buf.String(), "ZgotmplZ")
	})

	t.Run("a plain string redirect URL is exactly the regression this guards against", func(t *testing.T) {
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, "consent.html", gin.H{
			"AuthMethod":  "openid4vp",
			"RedirectURL": customSchemeURL, // deliberately NOT template.URL(...)
		})
		require.NoError(t, err)
		require.NotContains(t, buf.String(), customSchemeURL, "a plain string should NOT survive html/template's URL-attribute escaper for a non-allowlisted scheme -- if this fails, html/template's default behavior has changed and the template.URL(...) wrap in endpoints_oauth.go is no longer doing anything")
		require.Contains(t, buf.String(), "ZgotmplZ")
	})
}
