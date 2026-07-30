package httpserver

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointOpenIDFederationEntityConfig serves the OpenID Federation entity configuration
// at /.well-known/openid-federation as a self-signed JWT per OpenID Federation 1.0 §5.2.
func (s *Service) endpointOpenIDFederationEntityConfig(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOpenIDFederationEntityConfig")
	defer span.End()

	reply, err := s.apiv1.OpenIDFederationEntityConfig(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if !reply.Enabled {
		c.AbortWithStatus(http.StatusNotFound)
		return nil, nil
	}

	c.Data(http.StatusOK, "application/entity-statement+jwt", []byte(reply.JWT))
	return nil, nil
}
