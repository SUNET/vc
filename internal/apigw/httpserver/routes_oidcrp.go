package httpserver

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// registerOIDCRPRoutes registers OIDC RP-specific endpoints when OIDC RP is enabled
func (s *Service) registerOIDCRPRoutes(ctx context.Context, rgRoot *gin.RouterGroup) {
	rgOIDCRP := rgRoot.Group("/oidcrp")

	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCRP, http.MethodPost, "/initiate", http.StatusOK, s.endpointOIDCRPInitiate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCRP, http.MethodGet, "/callback", http.StatusOK, s.endpointOIDCRPCallback)

	s.log.Info("OIDC RP endpoints registered")
}
