package httpserver

import (
	"context"
	"net/http"
	"github.com/SUNET/vc/internal/verifier/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointSessionPreference handles session preference updates
func (s *Service) endpointSessionPreference(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSessionPreference")
	defer span.End()

	request := &apiv1.UpdateSessionPreferenceRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind session preference request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	response, err := s.apiv1.UpdateSessionPreference(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to update session preference")
		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	return response, nil
}

// endpointCredentialDisplay shows the credential display page
func (s *Service) endpointCredentialDisplay(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCredentialDisplay")
	defer span.End()

	request := &apiv1.GetCredentialDisplayDataRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Get display data
	response, err := s.apiv1.GetCredentialDisplayData(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get credential display data")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	// Render credential display page
	c.HTML(http.StatusOK, "credential_display.html", gin.H{
		"SessionID":         response.SessionID,
		"VPToken":           response.VPToken,
		"Claims":            response.Claims,
		"ClientID":          response.ClientID,
		"RedirectURI":       response.RedirectURI,
		"State":             response.State,
		"ShowRawCredential": response.ShowRawCredential,
		"ShowClaims":        response.ShowClaims,
		"PrimaryColor":      response.PrimaryColor,
		"SecondaryColor":    response.SecondaryColor,
		"CustomCSS":         response.CustomCSS,
	})

	return nil, nil
}

// endpointConfirmCredentialDisplay handles confirmation from credential display page
func (s *Service) endpointConfirmCredentialDisplay(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointConfirmCredentialDisplay")
	defer span.End()

	request := &apiv1.ConfirmCredentialDisplayRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind confirmation request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	response, err := s.apiv1.ConfirmCredentialDisplay(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to confirm credential display")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	// Return redirect URI for the client to use
	return response, nil
}
