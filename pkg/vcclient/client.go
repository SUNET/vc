package vcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
)

// Client is the client
type Client struct {
	httpClient *http.Client
	log        *logger.Log
	APIGW      *APIGWClient
	MockAS     *MockASClient
	Verifier   *VerifierClient
}

// APIGWClient handles all APIGW endpoints
type APIGWClient struct {
	client   *Client
	baseURL  string
	log      *logger.Log
	Document *documentHandler
	Identity *identityHandler
	Root     *rootHandler
	OAuth    *oauthHandler
	User     *userHandler
}

// MockASClient handles MockAS endpoints
type MockASClient struct {
	client  *Client
	baseURL string
	log     *logger.Log
	Root    *mockasRootHandler
	Mock    *mockHandler
}

// VerifierClient handles Verifier endpoints
type VerifierClient struct {
	client  *Client
	baseURL string
	log     *logger.Log
}

// Config is the configuration for the client
type Config struct {
	ApigwURL    string `validate:""`
	MockASURL   string `validate:""`
	VerifierURL string `validate:""`
}

// New creates a new client
func New(config *Config, log *logger.Log) (*Client, error) {
	if err := helpers.CheckSimple(config); err != nil {
		return nil, err
	}
	c := &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		log: log.New("vcclient"),
	}

	defaultContentType := "application/json"

	// Initialize APIGW client if configured
	if config.ApigwURL != "" {
		c.APIGW = &APIGWClient{
			client:  c,
			baseURL: config.ApigwURL,
			log:     c.log.New("apigw"),
		}
		c.APIGW.Document = &documentHandler{client: c, serviceBaseURL: "api/v1/document", defaultContentType: defaultContentType, log: c.log.New("apigw.document"), baseURL: config.ApigwURL}
		c.APIGW.Identity = &identityHandler{client: c, serviceBaseURL: "api/v1/identity", defaultContentType: defaultContentType, log: c.log.New("apigw.identity"), baseURL: config.ApigwURL}
		c.APIGW.Root = &rootHandler{client: c, serviceBaseURL: "api/v1", defaultContentType: defaultContentType, log: c.log.New("apigw.root"), baseURL: config.ApigwURL}
		c.APIGW.OAuth = &oauthHandler{client: c, defaultContentType: defaultContentType, log: c.log.New("apigw.oauth"), baseURL: config.ApigwURL}
		c.APIGW.User = &userHandler{client: c, serviceBaseURL: "api/v1/user", defaultContentType: defaultContentType, log: c.log.New("apigw.user"), baseURL: config.ApigwURL}
	}

	// Initialize MockAS client if configured
	if config.MockASURL != "" {
		c.MockAS = &MockASClient{
			client:  c,
			baseURL: config.MockASURL,
			log:     c.log.New("mockas"),
		}
		c.MockAS.Root = &mockasRootHandler{client: c, baseURL: config.MockASURL, log: c.log.New("mockas.root")}
		c.MockAS.Mock = &mockHandler{client: c, serviceBaseURL: "api/v1/mock", defaultContentType: defaultContentType, log: c.log.New("mockas.mock"), baseURL: config.MockASURL}
	}

	// Initialize Verifier client if configured
	if config.VerifierURL != "" {
		c.Verifier = &VerifierClient{
			client:  c,
			baseURL: config.VerifierURL,
			log:     c.log.New("verifier"),
		}
	}

	return c, nil
}

// NewRequest make a new request
func (c *Client) newRequest(ctx context.Context, method, path, contentType string, body any, baseURL string) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		c.log.Error(err, "parse url", "path", path)
		return nil, err
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)
	c.log.Debug("request", "url", url.String())

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			c.log.Error(err, "failed to encode body")
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", contentType)
		c.log.Debug("request", "Content-Type", req.Header.Get("Content-Type"))
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Do does the new request
func (c *Client) do(ctx context.Context, req *http.Request, reply any, prefixReplyJSONWithData bool) (*http.Response, error) {
	// Validate request URL scheme to prevent SSRF
	if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL scheme: %v", req.URL)
	}
	resp, err := c.httpClient.Do(req) //#nosec G704 -- URL from trusted config (baseURL)
	if err != nil {
		return nil, err
	}

	//defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(buf.Bytes(), err); err != nil {
			return nil, err
		}
		c.log.Error(err, "response error", "body", buf.String())
		return nil, err
	}

	// Skip decoding if no reply is expected
	if reply == nil {
		return resp, nil
	}

	var r any
	if prefixReplyJSONWithData {
		r = &struct {
			Data any `json:"data"`
		}{
			Data: reply,
		}
	} else {
		r = &reply
	}

	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		c.log.Error(err, "failed to decode response")
		return nil, err
	}

	return resp, nil

}

// read body and make it reusable
//func readBody(body io.ReadCloser) ([]byte, error) {
//	buf := &bytes.Buffer{}
//	if _, err := buf.ReadFrom(body); err != nil {
//		return nil, err
//	}
//	return buf.Bytes(), nil
//}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 302, 304:
		return nil
	case 500:
		return ErrInvalidRequest
	case 401:
		return ErrNotAllowedRequest
	}

	return ErrInvalidRequest
}

func (c *Client) call(ctx context.Context, method, path, contentType string, body, reply any, prefixReplyJSONWithData bool, baseURL string) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		path,
		contentType,
		body,
		baseURL,
	)
	if err != nil {
		c.log.Error(err, "call failed", "method", method, "path", path)
		return nil, err
	}

	resp, err := c.do(ctx, request, reply, prefixReplyJSONWithData)
	if err != nil {
		c.log.Error(err, "do failed", "method", method, "path", path)
		return resp, err
	}

	return resp, nil
}
