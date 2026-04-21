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
//
//	@Summary		Initiate OIDC Authentication
//	@Description	Initiates OIDC authentication by generating an OAuth2 authorization URL with PKCE
//	@Tags			OIDCRP
//	@Accept			json
//	@Produce		json
//	@Param			request	body		apiv1.OIDCRPInitiateRequest	true	"OIDC RP initiate request"
//	@Success		200		{object}	apiv1.OIDCRPInitiateResponse
//	@Failure		400		{object}	map[string]any	"Bad request"
//	@Failure		500		{object}	map[string]any	"Internal server error"
//	@Router			/oidcrp/initiate [post]
func (s *Service) endpointOIDCRPInitiate(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPInitiate")
	defer span.End()

	if s.oidcrpService == nil {
		span.SetStatus(codes.Error, "OIDC RP not configured")
		return nil, fmt.Errorf("OIDC RP is not enabled")
	}

	var req apiv1.OIDCRPInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Delegate to apiv1 layer
	return s.apiv1.OIDCRPInitiate(ctx, &req, s.oidcrpService)
}

// endpointOIDCRPCallback handles the OIDC Provider callback
// This is where the OIDC Provider redirects after authentication
//
//	@Summary		OIDC Provider Callback
//	@Description	Receives and processes the authorization code from the OIDC Provider
//	@Tags			OIDCRP
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			code	query		string	true	"Authorization code"
//	@Param			state	query		string	true	"OAuth2 state parameter"
//	@Success		200		{object}	apiv1.OIDCRPCallbackResponse
//	@Failure		400		{object}	map[string]any	"Bad request"
//	@Failure		500		{object}	map[string]any	"Internal server error"
//	@Router			/oidcrp/callback [get]
func (s *Service) endpointOIDCRPCallback(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRPCallback")
	defer span.End()

	if s.oidcrpService == nil {
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
		span.SetStatus(codes.Error, "missing code or state parameter")
		return nil, fmt.Errorf("missing required parameters: code and state")
	}

	// Delegate to apiv1 layer
	reply, err := s.apiv1.OIDCRPCallback(ctx, req, s.oidcrpService)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// VCI mode: redirect browser back to consent page
	if reply != nil && reply.VCIRedirectURL != "" {
		c.Redirect(http.StatusFound, reply.VCIRedirectURL)
		return nil, nil
	}

	return reply, nil
}
