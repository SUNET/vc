package httphelpers

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/httphelpers/staticembed"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/gin-gonic/gin"
)

type renderingHandler struct {
	client    *Client
	log       *logger.Log
	errorTmpl *template.Template
}

// errorPageTemplate parses the shared HTML error page once at startup.
func errorPageTemplate() *template.Template {
	return template.Must(template.ParseFS(staticembed.FS, "error.html"))
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
		if isOIDCEndpoint(c.Request.URL.Path) {
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
// error page rather than JSON. Only genuine browser navigations qualify: the
// request must explicitly list text/html (not merely */*, which every API
// client and curl sends), the status must be an error, and the path must not
// be an API/OIDC endpoint that is contractually JSON.
func (r *renderingHandler) wantsErrorHTML(c *gin.Context, code int) bool {
	if code < 400 {
		return false
	}
	if isOIDCEndpoint(c.Request.URL.Path) {
		return false
	}
	return strings.Contains(c.GetHeader("Accept"), gin.MIMEHTML)
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
	}{
		Code:       code,
		StatusText: http.StatusText(code),
		Message:    message,
		RequestID:  c.GetString("req_id"),
	}

	var buf bytes.Buffer
	if err := r.errorTmpl.ExecuteTemplate(&buf, "error.html", page); err != nil {
		r.log.Error(err, "failed to render error page")
		c.JSON(code, data)
		return
	}

	c.Data(code, gin.MIMEHTML+"; charset=utf-8", buf.Bytes())
}

// isOIDCEndpoint checks if the path is an OIDC/OAuth2 endpoint that must return JSON
func isOIDCEndpoint(path string) bool {
	// OIDC and OAuth2 endpoints that MUST return application/json per spec
	oidcIndicators := []string{
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
	}

	for _, indicator := range oidcIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}
