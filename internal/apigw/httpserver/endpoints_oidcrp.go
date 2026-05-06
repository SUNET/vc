package httpserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointOIDCRPInitiate initiates OIDC authentication flow
func (s *Service) endpointOIDCRPInitiate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPInitiate")
	defer span.End()

	s.log.Debug("endpointOIDCRPInitiate called")

	if s.authProviders.OIDC() == nil {
		span.SetStatus(codes.Error, "OIDC RP not configured")
		return nil, fmt.Errorf("OIDC RP is not enabled")
	}

	var req apiv1.OIDCRPInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Delegate to apiv1 layer
	return s.apiv1.OIDCRPInitiate(ctx, &req, s.authProviders.OIDC())
}

// endpointOIDCRPCallback handles the OIDC Provider callback
// This is where the OIDC Provider redirects after authentication
func (s *Service) endpointOIDCRPCallback(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPCallback")
	defer span.End()

	s.log.Debug("endpointOIDCRPCallback called", "query", c.Request.URL.RawQuery)

	if s.authProviders.OIDC() == nil {
		span.SetStatus(codes.Error, "OIDC RP not configured")
		return nil, fmt.Errorf("OIDC RP is not enabled")
	}

	// Extract query parameters and build request
	req := &apiv1.OIDCRPCallbackRequest{
		Code:  c.Query("code"),
		State: c.Query("state"),
	}

	// Check for IdP error responses (RFC 6749 §4.1.2.1)
	if idpError := c.Query("error"); idpError != "" {
		idpDesc := c.Query("error_description")
		s.log.Error(nil, "OIDC IdP returned error",
			"error", idpError,
			"error_description", idpDesc,
			"state", req.State)
		span.SetStatus(codes.Error, "IdP error: "+idpError)
		return nil, fmt.Errorf("identity provider error: %s - %s", idpError, idpDesc)
	}

	if req.Code == "" || req.State == "" {
		s.log.Debug("endpointOIDCRPCallback: missing code or state", "code_present", req.Code != "", "state_present", req.State != "")
		span.SetStatus(codes.Error, "missing code or state parameter")
		return nil, fmt.Errorf("missing required parameters: code and state")
	}

	s.log.Debug("endpointOIDCRPCallback: delegating to apiv1", "state", req.State)
	// Delegate to apiv1 layer
	reply, err := s.apiv1.OIDCRPCallback(ctx, req, s.authProviders.OIDC())
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// VCI mode: redirect browser back to consent page
	if reply != nil && reply.VCIRedirectURL != "" {
		s.log.Debug("endpointOIDCRPCallback: VCI mode, redirecting", "redirect_url", reply.VCIRedirectURL)
		c.Redirect(http.StatusFound, reply.VCIRedirectURL)
		return nil, nil
	}

	s.log.Debug("endpointOIDCRPCallback: standalone mode, returning response")
	return reply, nil
}
