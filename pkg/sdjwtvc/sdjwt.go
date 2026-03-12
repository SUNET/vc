package sdjwtvc

import (
	"net/http"
	"time"
)

const (
	// maxVCTMSize is the maximum allowed VCTM response body size (1 MiB).
	maxVCTMSize = 1 << 20

	// defaultHTTPTimeout is the timeout applied to the default HTTP client
	// used for VCTM fetches.
	defaultHTTPTimeout = 30 * time.Second
)

// Client is the SD-JWT VC client.
type Client struct {
	// HTTPClient is the HTTP client used for outbound requests (e.g. VCTM
	// fetches). When nil, a default client with a 30-second timeout is used.
	HTTPClient *http.Client
}

// New creates a new Client with sensible defaults.
func New() *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
}
