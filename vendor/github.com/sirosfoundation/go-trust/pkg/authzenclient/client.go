// Package authzenclient provides a standalone HTTP client for the AuthZEN protocol.package authzenclient

// This package implements a client for making AuthZEN trust evaluation requests
// to a Policy Decision Point (PDP) server. It supports:
//
//   - Discovery via .well-known/authzen-configuration endpoint
//   - Trust evaluation requests (/evaluation endpoint)
//   - Resolution-only requests for DID/metadata resolution
//   - Configurable HTTP transport with timeouts and retries
//
// # Basic Usage
//
// Create a client with a known PDP URL:
//
//	client := authzenclient.New("https://pdp.example.com")
//	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
//	    Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
//	    Resource: authzen.Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{jwk}},
//	})
//
// # Discovery
//
// Use discovery to automatically find the evaluation endpoint:
//
//	client, err := authzenclient.Discover(ctx, "https://pdp.example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	resp, err := client.Evaluate(ctx, req)
//
// # Resolution-Only Requests
//
// To resolve DID documents or entity configurations without key validation:
//
//	resp, err := client.Resolve(ctx, "did:web:example.com")
//	if resp.Decision {
//	    didDoc := resp.Context.TrustMetadata
//	}
//
// This package is designed to have minimal dependencies on other packages in go-trust,
// only importing the authzen types package.
package authzenclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

const (
	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// maxResponseBodyBytes is the maximum allowed HTTP response body size (10 MB).
	// This is the default for the authzenclient package; server-side code uses
	// registry.GetMaxResponseBodyBytes() which is configurable.
	maxResponseBodyBytes = 10 * 1024 * 1024

	// WellKnownPath is the discovery endpoint path.
	WellKnownPath = "/.well-known/authzen-configuration"

	// DefaultEvaluationPath is the default evaluation endpoint path.
	DefaultEvaluationPath = "/evaluation"
)

// Client is an AuthZEN PDP client.
type Client struct {
	// BaseURL is the base URL of the PDP server.
	BaseURL string

	// EvaluationEndpoint is the URL for the evaluation endpoint.
	// If empty, BaseURL + DefaultEvaluationPath is used.
	EvaluationEndpoint string

	// HTTPClient is the underlying HTTP client. If nil, a default client is used.
	HTTPClient *http.Client

	// Metadata contains the discovered PDP metadata, if discovery was used.
	Metadata *authzen.PDPMetadata
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.HTTPClient = c
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(client *Client) {
		if client.HTTPClient == nil {
			client.HTTPClient = &http.Client{}
		}
		client.HTTPClient.Timeout = d
	}
}

// WithEvaluationEndpoint sets a custom evaluation endpoint URL.
func WithEvaluationEndpoint(endpoint string) Option {
	return func(client *Client) {
		client.EvaluationEndpoint = endpoint
	}
}

// New creates a new AuthZEN client with the given base URL.
func New(baseURL string, opts ...Option) *Client {
	// Normalize base URL - remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	c := &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Discover creates a new AuthZEN client by discovering the PDP configuration
// from the .well-known/authzen-configuration endpoint.
func Discover(ctx context.Context, baseURL string, opts ...Option) (*Client, error) {
	// Normalize base URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	c := New(baseURL, opts...)

	// Fetch discovery document
	discoveryURL := baseURL + WellKnownPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		return nil, fmt.Errorf("discovery returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata authzen.PDPMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding discovery response: %w", err)
	}

	c.Metadata = &metadata

	// Use discovered endpoint if available
	if metadata.AccessEvaluationEndpoint != "" {
		c.EvaluationEndpoint = metadata.AccessEvaluationEndpoint
	}

	return c, nil
}

// evaluationURL returns the evaluation endpoint URL.
func (c *Client) evaluationURL() string {
	if c.EvaluationEndpoint != "" {
		return c.EvaluationEndpoint
	}
	return c.BaseURL + DefaultEvaluationPath
}

// Evaluate sends a trust evaluation request to the PDP.
func (c *Client) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Validate request before sending
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return c.doEvaluate(ctx, req)
}

// EvaluateRaw sends a trust evaluation request without client-side validation.
// Use this if you need to send requests that may not pass strict validation.
func (c *Client) EvaluateRaw(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return c.doEvaluate(ctx, req)
}

// doEvaluate performs the actual HTTP request.
func (c *Client) doEvaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.evaluationURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close() //nolint:errcheck // Body close error is not actionable

	// Read response body (limited to prevent unbounded memory use)
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if len(respBody) > maxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes", maxResponseBodyBytes)
	}

	// Handle error responses
	if httpResp.StatusCode != http.StatusOK {
		return nil, &EvaluationError{
			StatusCode: httpResp.StatusCode,
			Body:       string(respBody),
		}
	}

	var resp authzen.EvaluationResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &resp, nil
}

// Resolve sends a resolution-only request to retrieve trust metadata
// (DID document, entity configuration, etc.) without key validation.
func (c *Client) Resolve(ctx context.Context, subjectID string) (*authzen.EvaluationResponse, error) {
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   subjectID,
		},
		Resource: authzen.Resource{
			ID: subjectID,
			// Type and Key intentionally empty for resolution-only
		},
	}

	return c.doEvaluate(ctx, req)
}

// ResolveWithAction sends a resolution-only request with an action constraint.
func (c *Client) ResolveWithAction(ctx context.Context, subjectID, actionName string) (*authzen.EvaluationResponse, error) {
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   subjectID,
		},
		Resource: authzen.Resource{
			ID: subjectID,
		},
		Action: &authzen.Action{
			Name: actionName,
		},
	}

	return c.doEvaluate(ctx, req)
}

// EvaluateX5C is a convenience method for evaluating an X.509 certificate chain.
func (c *Client) EvaluateX5C(ctx context.Context, subjectID string, certChain []string, action *authzen.Action) (*authzen.EvaluationResponse, error) {
	// Convert string slice to interface slice
	keys := make([]interface{}, len(certChain))
	for i, cert := range certChain {
		keys[i] = cert
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   subjectID,
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   subjectID,
			Key:  keys,
		},
		Action: action,
	}

	return c.Evaluate(ctx, req)
}

// EvaluateJWK is a convenience method for evaluating a JWK.
func (c *Client) EvaluateJWK(ctx context.Context, subjectID string, jwk map[string]interface{}, action *authzen.Action) (*authzen.EvaluationResponse, error) {
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   subjectID,
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   subjectID,
			Key:  []interface{}{jwk},
		},
		Action: action,
	}

	return c.Evaluate(ctx, req)
}

// EvaluationError represents an error response from the PDP.
type EvaluationError struct {
	StatusCode int
	Body       string
}

func (e *EvaluationError) Error() string {
	return fmt.Sprintf("evaluation failed with status %d: %s", e.StatusCode, e.Body)
}

// IsEvaluationError checks if an error is an EvaluationError and returns it.
func IsEvaluationError(err error) (*EvaluationError, bool) {
	evalErr, ok := err.(*EvaluationError)
	return evalErr, ok
}

// ParseBaseURL parses and validates a PDP base URL.
func ParseBaseURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("URL must use http or https scheme, got %s", u.Scheme)
	}

	if u.Host == "" {
		return "", fmt.Errorf("URL must have a host")
	}

	// Return normalized URL without path, query, fragment
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
