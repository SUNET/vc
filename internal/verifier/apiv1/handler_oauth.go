package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/oauth2"
)

func (c *Client) OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error) {
	c.log.Debug("metadata request")

	// Sign metadata with fresh signature on each request
	signedMetadata, err := c.oauth2Metadata.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		return nil, err
	}

	c.log.Debug("after signing")

	if err := helpers.Check(ctx, c.cfg, signedMetadata, c.log); err != nil {
		c.log.Error(err, "metadata check error")
		return nil, err
	}

	c.log.Debug("after check")

	return signedMetadata, nil
}
