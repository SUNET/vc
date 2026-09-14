package httpserver

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointDashboard(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDashboard")
	defer span.End()

	reply, err := s.apiv1.Dashboard(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	c.HTML(http.StatusOK, "dashboard.html", reply)
	return nil, nil
}
