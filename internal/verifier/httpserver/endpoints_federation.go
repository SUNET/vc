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
	cfg := s.cfg.Verifier.Federation
	if cfg == nil || !cfg.Enabled {
		c.Status(http.StatusNotFound)
		return nil, nil
	}

	signer := pki.NewSignerConfig(s.cfg.Verifier.KeyConfig)
	svc := federation.NewService(cfg, signer, s.cfg.Verifier.PublicURL)

	// Derive signing algorithm from the actual key configuration
	jwk, err := signer.GetJWK()
	if err != nil {
		return nil, err
	}

	// Build metadata advertising this service as an OpenID Relying Party (verifier)
	metadata := &federation.EntityMetadata{
		OpenIDRelyingParty: map[string]any{
			"client_id":                  svc.EntityID(),
			"response_types":             []string{"vp_token"},
			"vp_formats":                 s.cfg.Verifier.PreferredVPFormats,
			"client_name":                cfg.OrganizationName,
			"request_object_signing_alg": jwk.Algorithm,
		},
	}

	signed, err := svc.BuildEntityConfiguration(metadata)
	if err != nil {
		return nil, err
	}

	c.Data(http.StatusOK, "application/entity-statement+jwt", []byte(signed))
	return nil, nil
}
