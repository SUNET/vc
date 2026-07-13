package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/pkg/federation"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/gin-gonic/gin"
)

// endpointFederationEntityConfig serves the OpenID Federation entity configuration
// at /.well-known/openid-federation as a self-signed JWT per OpenID Federation 1.0 §5.2.
func (s *Service) endpointFederationEntityConfig(ctx context.Context, c *gin.Context) (any, error) {
	cfg := s.cfg.APIGW.Federation
	if cfg == nil || !cfg.Enabled {
		c.Status(http.StatusNotFound)
		return nil, nil
	}

	signer := pki.NewSignerConfig(s.cfg.APIGW.KeyConfig)
	svc := federation.NewService(cfg, signer, s.cfg.APIGW.PublicURL)

	// Build metadata from existing issuer/OAuth2 metadata
	metadata := &federation.EntityMetadata{
		OpenIDCredentialIssuer: map[string]any{
			"credential_issuer":  s.cfg.APIGW.PublicURL,
			"credential_endpoint": s.cfg.APIGW.PublicURL + "/credential",
		},
		OAuthAuthorizationServer: map[string]any{
			"issuer":                 s.cfg.APIGW.PublicURL,
			"token_endpoint":         s.cfg.APIGW.PublicURL + "/token",
			"authorization_endpoint": s.cfg.APIGW.PublicURL + "/authorize",
		},
	}

	signed, err := svc.BuildEntityConfiguration(metadata)
	if err != nil {
		return nil, err
	}

	c.Data(http.StatusOK, "application/entity-statement+jwt", []byte(signed))
	return nil, nil
}
