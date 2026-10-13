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
func parseMediaRange(part string) (string, float64) {
	segs := strings.Split(part, ";")
	mediaRange := strings.ToLower(strings.TrimSpace(segs[0]))
	if mediaRange == "" {
		return "", 0
	}

	q := 1.0
	for _, param := range segs[1:] {
		param = strings.TrimSpace(param)
		if after, ok := strings.CutPrefix(param, "q="); ok {
			if v, err := strconv.ParseFloat(strings.TrimSpace(after), 64); err == nil {
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
	}

	for _, indicator := range jsonOnlyIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}
