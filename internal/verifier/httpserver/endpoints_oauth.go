package httpserver

import (
	"context"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointOAuthPar(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthPar")
	defer span.End()

	s.log.Debug("endpointOAuthPar")
	request := &openid4vci.PARRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	//reply, err := s.apiv1.OAuthPar(ctx, request)
	//if err != nil {
	//	span.SetStatus(codes.Error, err.Error())
	//	s.log.Error(err, "par error")
	//	if errors.Is(err, oauth2.ErrInvalidClient) {
	//		c.AbortWithStatus(http.StatusMethodNotAllowed)
	//		return nil, nil
	//	}
	//	return nil, err
	//}
	//s.log.Debug("par", "reply", reply)

	return nil, nil
}

func (s *Service) endpointOAuthMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.OAuthMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}
