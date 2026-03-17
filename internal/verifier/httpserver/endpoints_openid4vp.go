package httpserver

import (
	"context"
	"net/http"
	"vc/internal/verifier/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointOIDCRequestObject handles OpenID4VP request object retrieval (for OIDC flow)
func (s *Service) endpointOIDCRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCRequestObject")
	defer span.End()

	s.log.Debug("endpointOIDCRequestObject called")

	request := &apiv1.GetRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Get request object
	response, err := s.apiv1.GetOIDCRequestObject(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get request object")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	c.Header("Content-Type", "application/oauth-authz-req+jwt")
	c.String(http.StatusOK, response.RequestObject)
	return nil, nil
}

// endpointOIDCDirectPost handles OpenID4VP direct_post responses from wallet (for OIDC flow)
func (s *Service) endpointOIDCDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCDirectPost")
	defer span.End()

	s.log.Debug("endpointOIDCDirectPost called")

	// Parse request - httpHelpers.Binding.Request handles JSON, form-encoded, and query params
	request := &apiv1.DirectPostRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind direct_post request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Process VP token
	response, err := s.apiv1.ProcessDirectPost(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to process direct_post")

		// Return error response per OpenID4VP spec
		c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return nil, nil
	}

	// Per OpenID4VP spec Section 7.2, the direct_post response MUST be
	// 200 OK with a JSON body. A 302 redirect would cause the wallet to
	// follow it and consume the authorization code before the browser can.
	// The browser picks up the redirect via the poll endpoint instead.
	if response.RedirectURI != "" {
		c.JSON(http.StatusOK, gin.H{
			"redirect_uri": response.RedirectURI,
		})
		return nil, nil
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil, nil
}

// endpointOIDCCallback handles callback requests (for OIDC flow)
func (s *Service) endpointOIDCCallback(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCCallback")
	defer span.End()

	s.log.Debug("endpointOIDCCallback called")

	request := &apiv1.CallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind callback request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	response, err := s.apiv1.ProcessCallback(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to process callback")
		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	// Redirect to RP
	if response.RedirectURI != "" {
		c.Redirect(http.StatusFound, response.RedirectURI)
		return nil, nil
	}

	c.AbortWithStatus(http.StatusOK)
	return nil, nil
}

// endpointQRCode generates a QR code for a session
func (s *Service) endpointQRCode(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQRCode")
	defer span.End()

	request := &apiv1.GetQRCodeRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	response, err := s.apiv1.GetQRCode(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to generate QR code")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	c.Header("Content-Type", "image/png")
	c.Data(http.StatusOK, "image/png", response.ImageData)
	return nil, nil
}

// endpointPollSession polls the session status
func (s *Service) endpointPollSession(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointPollSession")
	defer span.End()

	request := &apiv1.PollSessionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	response, err := s.apiv1.PollSession(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to poll session")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	return response, nil
}
