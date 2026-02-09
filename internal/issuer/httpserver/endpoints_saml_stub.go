//go:build !saml

package httpserver

import (
	"context"

	"github.com/gin-gonic/gin"
)

// Stub SAML endpoint implementations when SAML is not compiled in
// These functions will never be called because s.samlService will be nil,
// but they satisfy the compiler

func (s *Service) endpointSAMLMetadata(ctx context.Context, c *gin.Context) (any, error) {
	return nil, nil
}

func (s *Service) endpointSAMLInitiate(ctx context.Context, c *gin.Context) (any, error) {
	return nil, nil
}

func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (any, error) {
	return nil, nil
}
