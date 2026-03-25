package httphelpers

import (
	"context"
	"strings"
	"time"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/gin-gonic/gin"
)

type renderingHandler struct {
	client *Client
	log    *logger.Log
}

// Content renders the content
func (r *renderingHandler) Content(ctx context.Context, c *gin.Context, code int, data any) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, span := r.client.tracer.Start(ctx, "httphelpers:Render:Content")
	defer span.End()

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

// isOIDCEndpoint checks if the path is an OIDC/OAuth2 endpoint that must return JSON
func isOIDCEndpoint(path string) bool {
	// OIDC and OAuth2 endpoints that MUST return application/json per spec
	oidcIndicators := []string{
		"well-known",
		"/jwks",
		"/register",
		"/token",
		"/userinfo",
	}

	for _, indicator := range oidcIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}
