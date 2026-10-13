package oeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"golang.org/x/sync/singleflight"
)

// Client is an HTTP client for Open Education API (OEAPI) v6.0 endpoints.
// It handles OAuth 2.0 Client Credentials Grant (CCG) token management.
type Client struct {
	baseURL    string
	httpClient *http.Client
	log        *logger.Log

	// OAuth 2.0 CCG credentials
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string

	// Token cache
	tokenCache cache.Cache[string]

	// tokenGroup single-flights concurrent token refreshes.
	tokenGroup singleflight.Group
}

// ClientConfig holds configuration for creating a new OEAPI client.
type ClientConfig struct {
	BaseURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Timeout      time.Duration
	TokenCache   cache.Cache[string]
}

// NewClient creates a new OEAPI client.
// cfg.TokenCache must be set; the caller is responsible for providing a cache instance.
func NewClient(cfg ClientConfig, log *logger.Log) (*Client, error) {
	if cfg.TokenCache == nil {
		return nil, fmt.Errorf("oeapi: TokenCache is required")
	}
	client := &Client{
		baseURL:      cfg.BaseURL,
		httpClient:   &http.Client{Timeout: cfg.Timeout},
		log:          log.New("oeapi"),
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scopes:       cfg.Scopes,
		tokenCache:   cfg.TokenCache,
	}

	return client, nil
}

// tokenResponse is the OAuth 2.0 token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ensureToken obtains or refreshes the OAuth 2.0 access token using CCG.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	const cacheKey = "access_token"

	// Return cached token if still valid.
	if token, ok := c.tokenCache.Get(ctx, cacheKey); ok {
		return token, nil
	}

	// Single-flight the refresh so the concurrent GETs in FetchAndStoreForVCI
	// issue at most one client-credentials request on a cold/expired cache.
	// Waiters share the winner's result; the recheck inside covers a token
	// stored between the miss above and entering the critical section.
	v, err, _ := c.tokenGroup.Do(cacheKey, func() (any, error) {
		if token, ok := c.tokenCache.Get(ctx, cacheKey); ok {
			return token, nil
		}
		return c.fetchToken(ctx)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// fetchToken performs the client-credentials token request and caches the result.
func (c *Client) fetchToken(ctx context.Context) (string, error) {
	const cacheKey = "access_token"

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	if len(c.scopes) > 0 {
		data.Set("scope", strings.Join(c.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("oeapi: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oeapi: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Limit error body to 2 MB to prevent OOM from malicious/misconfigured server
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return "", fmt.Errorf("oeapi: token request returned %d (failed to read body: %w)", resp.StatusCode, err)
		}
		return "", fmt.Errorf("oeapi: token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("oeapi: decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("oeapi: token response contained empty access_token")
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	// Subtract 30s buffer so we refresh before actual expiry.
	if ttl > 30*time.Second {
		ttl -= 30 * time.Second
	}
	if ttl > 0 {
		c.tokenCache.SetWithTTL(ctx, cacheKey, tokenResp.AccessToken, ttl)
	} else {
		// No expires_in: use the cache default (1 hour).
		c.tokenCache.Set(ctx, cacheKey, tokenResp.AccessToken)
	}

	c.log.Info("OAuth 2.0 token obtained", "expires_in", tokenResp.ExpiresIn)
	return tokenResp.AccessToken, nil
}

// doGet performs an authenticated GET request to the OEAPI.
func (c *Client) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := c.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("oeapi: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.oeapi+json, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oeapi: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB
	if err != nil {
		return nil, fmt.Errorf("oeapi: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oeapi: GET %s returned %d: %s", path, resp.StatusCode, string(body))
	}

	return body, nil
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
// in the response instead of being returned as bare IDs.
func WithExpand(items ...string) QueryOption {
	return func(q url.Values) {
		for _, item := range items {
			q.Add("expand", item)
		}
	}
}

func buildQuery(opts []QueryOption) url.Values {
	q := url.Values{}
	for _, opt := range opts {
		opt(q)
	}
	return q
}
