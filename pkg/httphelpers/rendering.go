package httphelpers

import (
	"bytes"
	"context"
	"encoding/base64"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/httphelpers/staticembed"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
)

type renderingHandler struct {
	client      *Client
	log         *logger.Log
	errorTmpl   *template.Template
	logoDataURI template.URL
}

// errorPageTemplate parses the shared HTML error page once at startup.
func errorPageTemplate() *template.Template {
	return template.Must(template.ParseFS(staticembed.FS, "error.html"))
}

// errorPageLogo builds the data URI the error page renders its brand mark from.
// A readable common.branding.logo_path overrides the built-in SUNET logo, the
// same operator override CustomBranding applies to /static/logo.png; otherwise
// the embedded logo is used so the page stays self-contained on services that
// serve no /static route. Read once at startup, so a change needs a restart.
func errorPageLogo(branding model.Branding) template.URL {
	if branding.LogoPath != "" {
		if b, err := os.ReadFile(filepath.Clean(branding.LogoPath)); err == nil {
			return logoDataURI(b)
		}
	}
	if b, err := staticembed.FS.ReadFile("logo.png"); err == nil {
		return logoDataURI(b)
	}
	return ""
}

func logoDataURI(png []byte) template.URL {
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

// Content renders the content
func (r *renderingHandler) Content(ctx context.Context, c *gin.Context, code int, data any) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, span := r.client.tracer.Start(ctx, "httphelpers:Render:Content")
	defer span.End()

	// Browser navigations to a failed non-API endpoint get the shared HTML
	// error page instead of raw JSON. API and OIDC clients, and anything that
	// did not explicitly ask for text/html, keep their JSON.
	if r.wantsErrorHTML(c, code) {
		r.renderErrorHTML(c, code, data)
		return
	}

	negotiated := c.NegotiateFormat(gin.MIMEJSON, gin.MIMEPlain, gin.MIMEHTML, "*/*")

	switch negotiated {
	case gin.MIMEJSON:
		c.JSON(code, data)
	case gin.MIMEPlain, gin.MIMEHTML:
		// For OIDC and OAuth2 well-known endpoints, always return JSON per spec
		// even if text/plain is requested in Accept header
		if isJSONOnlyPath(c.Request.URL.Path) {
			c.JSON(code, data)
		} else {
			c.String(code, "%v", data)
		}
	case "*/*": // curl
		c.JSON(code, data)
	default:
		c.JSON(406, gin.H{"error": helpers.NewErrorDetails("not_acceptable", "Accept header is not supported. Supported types: application/json (text/plain, text/html).")})
	}
}

// wantsErrorHTML reports whether this failed response should be the shared HTML
// error page rather than JSON. It qualifies only when the status is an error,
// the path is not a JSON-only API/OIDC endpoint, and the client named
// text/html explicitly and preferred it to JSON (see prefersHTML).
func (r *renderingHandler) wantsErrorHTML(c *gin.Context, code int) bool {
	if code < 400 {
		return false
	}
	if isJSONOnlyPath(c.Request.URL.Path) {
		return false
	}
	return prefersHTML(c.GetHeader("Accept"))
}

// prefersHTML parses an Accept header and reports whether the client named
// text/html explicitly with a nonzero quality and ranked it at least as high
// as JSON. A bare */* (curl, API clients), text/html;q=0, or an Accept that
// prefers application/json all return false, so only a genuine browser
// navigation gets HTML.
func prefersHTML(accept string) bool {
	var qHTML float64
	htmlNamed := false

	// JSON quality per specificity tier; -1 means the tier was not named, so a
	// more specific range always wins over a wildcard fallback (RFC 7231).
	qJSONExact, qJSONType, qStar := -1.0, -1.0, -1.0

	for _, part := range strings.Split(accept, ",") {
		mediaRange, q := parseMediaRange(part)
		switch mediaRange {
		case "":
			continue
		case "text/html":
			htmlNamed = true
			if q > qHTML {
				qHTML = q
			}
		case "application/json":
			if q > qJSONExact {
				qJSONExact = q
			}
		case "application/*":
			if q > qJSONType {
				qJSONType = q
			}
		case "*/*":
			if q > qStar {
				qStar = q
			}
		}
	}

	// The most specific JSON range the client named sets its quality; an
	// explicit application/json;q=0 therefore beats a */*;q=1 fallback.
	qJSON := 0.0
	switch {
	case qJSONExact >= 0:
		qJSON = qJSONExact
	case qJSONType >= 0:
		qJSON = qJSONType
	case qStar >= 0:
		qJSON = qStar
	}

	return htmlNamed && qHTML > 0 && qHTML >= qJSON
}

// parseMediaRange splits one Accept entry into its lowercased media range and
// its quality value, defaulting q to 1 when absent or malformed.
//
// The parameter is matched case-insensitively. Parameter names are
// case-insensitive per RFC 9110 5.6.6, and "Q=" does occur; read as a name
// this did not recognise, the entry kept the default quality of 1, so a client
// writing "text/html;Q=0" - refusing HTML - was served the HTML error page,
// and on the Accept-Language side a refused language stayed a preference.
// Lowercasing the whole parameter is safe because the only one read here is a
// number.
func parseMediaRange(part string) (string, float64) {
	// Cut rather than Split: Split allocates a slice for every entry, and the
	// entry count is the client's to choose. A 1 MB Accept-Language of
	// one-subtag ranges allocated 62 MB and 699k objects parsing it, which is
	// a poor exchange for a request that costs the sender a megabyte.
	value, rest, _ := strings.Cut(part, ";")
	mediaRange := strings.ToLower(strings.TrimSpace(value))
	if mediaRange == "" {
		return "", 0
	}

	q := 1.0
	for rest != "" {
		var param string
		param, rest, _ = strings.Cut(rest, ";")
		param = strings.ToLower(strings.TrimSpace(param))
		if after, ok := strings.CutPrefix(param, "q="); ok {
			// Outside 0..1 is as malformed as unparsable: RFC 9110 12.4.2
			// admits only "0[.0*3]" and "1[.0*3]", so both are left at the
			// default rather than taken literally. Taken literally, "q=-1"
			// read as a refusal - silently dropping a language the client
			// had asked for, and doing it on exactly the kind of malformed
			// input that "q=notanumber" is already forgiven for - while
			// "q=5" outranked every well-formed preference beside it.
			//
			// A value INSIDE the range is honoured as written, including the
			// ones with more decimal places than the grammar admits: "0.0000"
			// and "0e0" parse to zero, and zero means not acceptable. Leaving
			// those at the default of 1 instead - the other reading of "not in
			// the grammar" - would turn an unmistakable refusal into the
			// client's top preference, which is the more harmful way to be
			// wrong. Deliberate; see the cases in accept_language_test.go.
			if v, err := strconv.ParseFloat(strings.TrimSpace(after), 64); err == nil && v >= 0 && v <= 1 {
				q = v
			}
		}
	}
	return mediaRange, q
}

// renderErrorHTML renders the shared error page. It surfaces only the safe
// error title and the request id; publicError has already redacted anything
// unclassified upstream, so no error detail is exposed here.
func (r *renderingHandler) renderErrorHTML(c *gin.Context, code int, data any) {
	message := ""
	if h, ok := data.(gin.H); ok {
		if herr, ok := h["error"].(*helpers.Error); ok {
			message = herr.Title
		}
	}

	page := struct {
		Code       int
		StatusText string
		Message    string
		RequestID  string
		LogoURI    template.URL
	}{
		Code:       code,
		StatusText: http.StatusText(code),
		Message:    message,
		RequestID:  c.GetString("req_id"),
		LogoURI:    r.logoDataURI,
	}

	var buf bytes.Buffer
	if err := r.errorTmpl.ExecuteTemplate(&buf, "error.html", page); err != nil {
		r.log.Error(err, "failed to render error page")
		c.JSON(code, data)
		return
	}

	c.Data(code, gin.MIMEHTML+"; charset=utf-8", buf.Bytes())
}

// isJSONOnlyPath reports whether a path must always return JSON rather than the
// HTML error page: the API surface and the OIDC/OAuth2 endpoints that are
// contractually application/json. Everything else is treated as browser-facing.
func isJSONOnlyPath(path string) bool {
	jsonOnlyIndicators := []string{
		"/api/",
		"well-known",
		"/jwks",
		"/register",
		"/token",
		"/userinfo",
		"/oidcrp/",
		"/samlsp/",
		"/op/par",
		"/nonce",
		"/credential",
		"/deferred_credential",
		"/notification",
		// OpenID4VP protocol routes a wallet drives, not browser pages;
		// substrings so the oidc-direct_post and :session_id variants match too.
		"request-object",
		"direct_post",
		// The Authorization Challenge Endpoint (OpenID4VCI 1.1). A wallet
		// posts to it and reads JSON back, in both directions: the success
		// body carries the authorization code and the 403 carries the
		// whole Interaction Required Response. Without this a request with
		// Accept: text/plain got "&{the-code}" from the %v renderer below,
		// and one with Accept: text/html got the HTML error page.
		"authorize-challenge",
	}

	for _, indicator := range jsonOnlyIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}
