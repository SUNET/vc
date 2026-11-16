package eduapi

import (
	"context"
	"net/url"

	"github.com/SUNET/vc/pkg/oauth2client"
)

// Client is an HTTP client for 1EdTech Edu-API v1.0 endpoints, backed by a
// shared OAuth 2.0 Client Credentials Grant HTTP client. The base URL must
// include the spec's base path, e.g. https://host/1edtech/eduapi/base/v1p0.
type Client struct {
	http *oauth2client.Client
}

// NewClient creates a new Edu-API client over the given CCG HTTP client.
func NewClient(http *oauth2client.Client) *Client {
	return &Client{http: http}
}

// doGet performs an authenticated GET to the Edu-API.
func (c *Client) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.http.Get(ctx, path, query)
}
