//go:build !saml

package httpserver

import (
	"context"

	"github.com/gin-gonic/gin"
)

// registerSAMLRoutes is a no-op when SAML is disabled
func (s *Service) registerSAMLRoutes(ctx context.Context, rgRoot *gin.RouterGroup) {
	// SAML not compiled in, no routes to register
	if s.cfg.APIGW.SAML.Enable {
		s.log.Info("SAML enabled in config but not compiled in. Rebuild with -tags saml")
	}
}

