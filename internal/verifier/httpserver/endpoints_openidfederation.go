package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/openidfederation"
	"github.com/gin-gonic/gin"
)

// endpointOpenIDFederationEntityConfig serves the OpenID Federation entity configuration
// at /.well-known/openid-federation as a self-signed JWT per OpenID Federation 1.0 §5.2.
// The underlying *openidfederation.Service (and its signer) is constructed
// once in New(), not per request.
func (s *Service) endpointOpenIDFederationEntityConfig(ctx context.Context, c *gin.Context) (any, error) {
	if s.openidFederationService == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return nil, nil
	}

	// Derive signing algorithm from the actual key configuration
	alg, err := s.openidFederationService.SigningAlgorithm()
	if err != nil {
		return nil, err
	}

	// Build metadata advertising this service as an OpenID Relying Party (verifier)
	metadata := &openidfederation.EntityMetadata{
		OpenIDRelyingParty: buildOpenIDRelyingPartyMetadata(
			s.openidFederationService.EntityID(),
			s.cfg.Verifier.OpenIDFederation.OrganizationName,
			alg,
			s.cfg.Verifier.PreferredVPFormats,
		),
	}

	signed, err := s.openidFederationService.BuildEntityConfiguration(metadata)
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
