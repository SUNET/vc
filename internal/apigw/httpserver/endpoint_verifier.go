package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// retrive Request object
func (s *Service) endpointVerificationRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerificationRequestObject")
	defer span.End()

	s.log.Debug("verification request object", "req", c.Request.Body, "headers", c.Request.Header)

	request := &apiv1.VerificationRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.VerificationRequestObject(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointVerificationDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointVerificationDirectPost")
	defer span.End()

	s.log.Debug("verification direct post", "headers", c.Request.Header)

	request := &apiv1.VerificationDirectPostRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.VerificationDirectPost(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}
