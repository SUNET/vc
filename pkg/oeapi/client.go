package oeapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/SUNET/vc/pkg/oauth2client"
)

// Client is an HTTP client for Open Education API (OEAPI) v6.0 endpoints,
// backed by a shared OAuth 2.0 Client Credentials Grant HTTP client.
type Client struct {
	http *oauth2client.Client
}

// NewClient creates a new OEAPI client over the given CCG HTTP client.
func NewClient(httpClient *oauth2client.Client) *Client {
	return &Client{http: httpClient}
}

// doGet performs an authenticated GET request to the OEAPI.
func (c *Client) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.http.Get(ctx, path, query)
}

// QueryOption configures optional query parameters for list endpoints.
type QueryOption func(q url.Values)

// WithPageSize sets the number of items per page (OEAPI allows 10, 20, 50, 100, 250).
func WithPageSize(n int) QueryOption {
	return func(q url.Values) {
		q.Set("pageSize", fmt.Sprintf("%d", n))
	}
}

// WithPageNumber sets the 1-based page number to retrieve.
func WithPageNumber(n int) QueryOption {
	return func(q url.Values) {
		q.Set("pageNumber", fmt.Sprintf("%d", n))
	}
}

// WithRole filters associations by role (e.g. "student").
func WithRole(role string) QueryOption {
	return func(q url.Values) {
		q.Set("role", role)
	}
}

// WithState filters associations by state (e.g. "associated").
func WithState(state string) QueryOption {
	return func(q url.Values) {
		q.Set("state", state)
	}
}

// WithExpand requests server-side expansion of referenced entities (e.g.
// "course_offering", "programme_offering") so their nested claims are embedded
// in the response instead of being returned as bare IDs. OEAPI declares expand
// as a non-exploded form array, so values are serialized comma-separated.
func WithExpand(items ...string) QueryOption {
	return func(q url.Values) {
		if len(items) == 0 {
			return
		}
		if existing := q.Get("expand"); existing != "" {
			items = append([]string{existing}, items...)
		}
		q.Set("expand", strings.Join(items, ","))
	}
}

func buildQuery(opts []QueryOption) url.Values {
	q := url.Values{}
	for _, opt := range opts {
		opt(q)
	}
	return q
}
