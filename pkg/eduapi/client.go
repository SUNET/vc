package eduapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/jellydator/ttlcache/v3"
)

// Client is an HTTP client for 1EdTech Edu-API v1.0 endpoints.
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
	tokenCache *ttlcache.Cache[string, string]
}

// ClientConfig holds configuration for creating a new Edu-API client.
type ClientConfig struct {
	BaseURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Timeout      time.Duration
}

// NewClient creates a new Edu-API client.
func NewClient(cfg ClientConfig, log *logger.Log) *Client {
	client := &Client{
		baseURL:      cfg.BaseURL,
		httpClient:   &http.Client{Timeout: cfg.Timeout},
		log:          log.New("eduapi"),
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scopes:       cfg.Scopes,
		tokenCache:   ttlcache.New(ttlcache.WithTTL[string, string](1 * time.Hour)),
	}

	return client
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
	if item := c.tokenCache.Get(cacheKey); item != nil {
		return item.Value(), nil
	}

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
		return "", fmt.Errorf("eduapi: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("eduapi: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("eduapi: token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("eduapi: decode token response: %w", err)
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	// Subtract 30s buffer so we refresh before actual expiry.
	if ttl > 30*time.Second {
		ttl -= 30 * time.Second
	}
	if ttl > 0 {
		c.tokenCache.Set(cacheKey, tokenResp.AccessToken, ttl)
	} else {
		// No expires_in: use the cache default (1 hour).
		c.tokenCache.Set(cacheKey, tokenResp.AccessToken, ttlcache.DefaultTTL)
	}

	c.log.Info("OAuth 2.0 token obtained", "expires_in", tokenResp.ExpiresIn)
	return tokenResp.AccessToken, nil
}

// doGet performs an authenticated GET request to the Edu-API.
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
		return nil, fmt.Errorf("eduapi: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eduapi: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("eduapi: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eduapi: GET %s returned %d: %s", path, resp.StatusCode, string(body))
	}

	return body, nil
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
