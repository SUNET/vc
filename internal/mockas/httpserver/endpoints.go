package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/vcclient"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointMockNext(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMockNext")
	defer span.End()

	request := &vcclient.MockNextRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.MockNext(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointMockBulk(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMockBulk")
	defer span.End()

	request := &vcclient.MockBulkRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.MockBulk(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointHealth")
	defer span.End()

	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
