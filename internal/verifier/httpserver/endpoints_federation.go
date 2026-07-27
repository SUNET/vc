package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/pkg/federation"
	"github.com/SUNET/vc/pkg/openid4vp"
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
		OpenIDRelyingParty: buildOpenIDRelyingPartyMetadata(
			svc.EntityID(),
			cfg.OrganizationName,
			jwk.Algorithm,
			s.cfg.Verifier.PreferredVPFormats,
		),
	}

	signed, err := svc.BuildEntityConfiguration(metadata)
	if err != nil {
		return nil, err
	}

	c.Data(http.StatusOK, "application/entity-statement+jwt", []byte(signed))
	return nil, nil
}

// buildOpenIDRelyingPartyMetadata builds the openid_relying_party metadata
// map advertised in the entity configuration. vpFormats is optional; the
// map is untyped (map[string]any), so a struct json tag can't omit an
// unset field for us -- the "vp_formats" key is only added when vpFormats
// is non-nil, to avoid serializing "vp_formats": null.
func buildOpenIDRelyingPartyMetadata(clientID, clientName, signingAlg string, vpFormats *openid4vp.VPFormatsSupported) map[string]any {
	m := map[string]any{
		"client_id":                  clientID,
		"response_types":             []string{"vp_token"},
		"client_name":                clientName,
		"request_object_signing_alg": signingAlg,
	}
	if vpFormats != nil {
		m["vp_formats"] = vpFormats
	}
	return m
}
