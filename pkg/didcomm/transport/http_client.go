package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SUNET/vc/pkg/didcomm"
)

// HTTPClient sends DIDComm messages over HTTP.
type HTTPClient struct {
	client    *http.Client
	userAgent string
}

// HTTPClientOption configures the HTTP client.
type HTTPClientOption func(*HTTPClient)

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(client *http.Client) HTTPClientOption {
	return func(c *HTTPClient) {
		c.client = client
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *HTTPClient) {
		c.client.Timeout = timeout
	}
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(userAgent string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.userAgent = userAgent
	}
}

// NewHTTPClient creates a new HTTP transport client.
func NewHTTPClient(opts ...HTTPClientOption) *HTTPClient {
	c := &HTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: "DIDComm/2.1",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SendRequest represents a DIDComm send request.
type SendRequest struct {
	// Endpoint is the target URL.
	Endpoint string

	// Message is the packed message bytes.
	Message []byte

	// MediaType is the content type of the message.
	MediaType string

	// ExpectReturn indicates whether a return route is expected.
	ExpectReturn bool
}

// SendResponse represents the response from sending a message.
type SendResponse struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Body is the response body (if any).
	Body []byte

	// MediaType is the content type of the response.
	MediaType string
}

// Send sends a DIDComm message to the specified endpoint.
func (c *HTTPClient) Send(ctx context.Context, req SendRequest) (*SendResponse, error) {
	if req.Endpoint == "" {
		return nil, ErrNoEndpoint
	}

	if req.MediaType == "" {
		req.MediaType = didcomm.MediaTypeEncrypted
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.Endpoint, bytes.NewReader(req.Message))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	httpReq.Header.Set("Content-Type", req.MediaType)
	if c.userAgent != "" {
		httpReq.Header.Set("User-Agent", c.userAgent)
	}

	// Per DIDComm HTTP spec, use Accept header to indicate expected response
	if req.ExpectReturn {
		httpReq.Header.Set("Accept", didcomm.MediaTypeEncrypted+", "+didcomm.MediaTypePlaintext)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrReceiveFailed, err)
	}

	return &SendResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		MediaType:  resp.Header.Get("Content-Type"),
	}, nil
}

// SendMessage is a convenience method that sends a message and returns just the response body.
func (c *HTTPClient) SendMessage(ctx context.Context, endpoint string, message []byte, mediaType string) ([]byte, error) {
	resp, err := c.Send(ctx, SendRequest{
		Endpoint:     endpoint,
		Message:      message,
		MediaType:    mediaType,
		ExpectReturn: true,
	})
	if err != nil {
		return nil, err
	}

	// Per DIDComm HTTP spec:
	// 202 Accepted - message received, no immediate response
	// 200 OK - response message in body
	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d: %s", ErrSendFailed, resp.StatusCode, string(resp.Body))
	}

	return resp.Body, nil
}
