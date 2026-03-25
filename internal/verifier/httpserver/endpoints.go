package httpserver

import (
	"context"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
