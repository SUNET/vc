package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/verifier/apiv1"

	"github.com/gin-gonic/gin"
)

// endpointRegisterClient handles OAuth 2.0 Dynamic Client Registration (RFC 7591)
func (s *Service) endpointRegisterClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointRegisterClient called")

	// Parse request body
	var req apiv1.ClientRegistrationRequest
	if err := s.httpHelpers.Binding.Request(ctx, c, &req); err != nil {
		s.log.Debug("Failed to parse registration request", "err", err)
		return nil, apiv1.NewInvalidRequestError("Invalid client metadata in request body")
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.RegisterClient(ctx, &req)
	if err != nil {
		s.log.Debug("Client registration failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointGetClientConfiguration handles retrieving client configuration (RFC 7592)
func (s *Service) endpointGetClientConfiguration(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointGetClientConfiguration called")

	request := &apiv1.GetClientInformationRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, apiv1.NewInvalidRequestError("Missing client_id parameter")
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.GetClientInformation(ctx, request)
	if err != nil {
		s.log.Debug("Get client configuration failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointUpdateClient handles updating client configuration (RFC 7592)
func (s *Service) endpointUpdateClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUpdateClient called")

	request := &apiv1.UpdateClientRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		s.log.Debug("Failed to parse update request", "err", err)
		return nil, apiv1.NewInvalidRequestError("Invalid client metadata in request body")
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.UpdateClient(ctx, request)
	if err != nil {
		s.log.Debug("Client update failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointDeleteClient handles deleting a client registration (RFC 7592)
func (s *Service) endpointDeleteClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointDeleteClient called")

	request := &apiv1.DeleteClientRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, apiv1.NewInvalidRequestError("Missing client_id parameter")
	}

	// Delegate to apiv1 layer
	err := s.apiv1.DeleteClient(ctx, request)
	if err != nil {
		s.log.Debug("Client deletion failed", "err", err)
		return nil, err
	}

	return nil, nil
}
