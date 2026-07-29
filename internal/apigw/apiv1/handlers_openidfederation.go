package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/openidfederation"
	"github.com/SUNET/vc/pkg/pki"
)

// OpenIDFederationEntityConfigReply carries the signed OpenID Federation entity
// configuration JWT, or Enabled=false when federation is not configured.
type OpenIDFederationEntityConfigReply struct {
	Enabled bool
	JWT     string
}

// OpenIDFederationEntityConfig builds and signs the OpenID Federation entity
// configuration served at /.well-known/openid-federation per OpenID
// Federation 1.0 §5.2.
func (c *Client) OpenIDFederationEntityConfig(ctx context.Context) (*OpenIDFederationEntityConfigReply, error) {
	cfg := c.cfg.APIGW.Federation
	if cfg == nil || !cfg.Enabled {
		return &OpenIDFederationEntityConfigReply{Enabled: false}, nil
	}

	signer := pki.NewSignerConfig(c.cfg.APIGW.KeyConfig)
	svc := openidfederation.NewService(cfg, signer, c.cfg.APIGW.PublicURL)

	// Build metadata from existing issuer/OAuth2 metadata
	metadata := &openidfederation.EntityMetadata{
		OpenIDCredentialIssuer: map[string]any{
			"credential_issuer":   c.cfg.APIGW.PublicURL,
			"credential_endpoint": c.cfg.APIGW.PublicURL + "/credential",
		},
		OAuthAuthorizationServer: map[string]any{
			"issuer":                 c.cfg.APIGW.PublicURL,
			"token_endpoint":         c.cfg.APIGW.PublicURL + "/token",
			"authorization_endpoint": c.cfg.APIGW.PublicURL + "/authorize",
		},
	}

	signed, err := svc.BuildEntityConfiguration(metadata)
	if err != nil {
		return nil, err
	}

	return &OpenIDFederationEntityConfigReply{Enabled: true, JWT: signed}, nil
}
