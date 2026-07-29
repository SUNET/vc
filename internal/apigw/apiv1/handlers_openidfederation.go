package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/openidfederation"
)

// OpenIDFederationEntityConfigReply carries the signed OpenID Federation entity
// configuration JWT, or Enabled=false when federation is not configured.
type OpenIDFederationEntityConfigReply struct {
	Enabled bool
	JWT     string
}

// OpenIDFederationEntityConfig builds and signs the OpenID Federation entity
// configuration served at /.well-known/openid-federation per OpenID
// Federation 1.0 §5.2. The underlying *openidfederation.Service (and its
// signer) is constructed once in New(), not per request.
func (c *Client) OpenIDFederationEntityConfig(ctx context.Context) (*OpenIDFederationEntityConfigReply, error) {
	if c.openidFederationService == nil {
		return &OpenIDFederationEntityConfigReply{Enabled: false}, nil
	}

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

	signed, err := c.openidFederationService.BuildEntityConfiguration(metadata)
	if err != nil {
		return nil, err
	}

	return &OpenIDFederationEntityConfigReply{Enabled: true, JWT: signed}, nil
}
