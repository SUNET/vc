package eduapi

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/pkg/oauth2client"
)

// Client is an HTTP client for 1EdTech Edu-API v1.0 endpoints, backed by a
// shared OAuth 2.0 Client Credentials Grant HTTP client.
type Client struct {
	http *oauth2client.Client
}

// NewClient creates a new Edu-API client over the given CCG HTTP client.
func NewClient(http *oauth2client.Client) *Client {
	return &Client{http: http}
}

// doGet performs an authenticated GET request to the Edu-API.
func (c *Client) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.http.Get(ctx, path, query)
}

// QueryOption configures optional query parameters for list endpoints.
type QueryOption func(q url.Values)

// WithLimit sets the maximum number of results.
func WithLimit(n int) QueryOption {
	return func(q url.Values) {
		q.Set("limit", fmt.Sprintf("%d", n))
	}
}

// WithOffset sets the pagination offset.
func WithOffset(n int) QueryOption {
	return func(q url.Values) {
		q.Set("offset", fmt.Sprintf("%d", n))
	}
}

// WithFilter adds an Edu-API filter expression.
func WithFilter(filter string) QueryOption {
	return func(q url.Values) {
		q.Set("filter", filter)
	}
}

// WithSort sets the sort field.
func WithSort(field string) QueryOption {
	return func(q url.Values) {
		q.Set("sort", field)
	}
}

// WithOrderBy sets the sort direction ("asc" or "desc").
func WithOrderBy(dir string) QueryOption {
	return func(q url.Values) {
		q.Set("orderBy", dir)
	}
}

func buildQuery(opts []QueryOption) url.Values {
	q := url.Values{}
	for _, opt := range opts {
		opt(q)
	}
	return q
}
