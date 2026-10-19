// Package oauth2client provides a small HTTP client that manages OAuth 2.0
// Client Credentials Grant (CCG) access tokens and performs authenticated GET
// requests. It is shared by the external-API data source clients (eduapi,
// oeapi) so the token-management logic lives in a single place.
package oauth2client

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

// Config configures a Client.
type Config struct {
	BaseURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Timeout      time.Duration

	// Accept is the Accept header sent on GET requests; defaults to
	// "application/json" when empty.
	Accept string

	// Name scopes the logger and prefixes returned errors (e.g. "eduapi").
	Name string

	// TokenCache stores the access token; required.
	TokenCache cache.Cache[string]
}

// Client performs CCG token management and authenticated GET requests.
type Client struct {
	baseURL    string
	accept     string
	name       string
	httpClient *http.Client
	log        *logger.Log

	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string

	tokenCache cache.Cache[string]
	tokenGroup singleflight.Group
}

// New creates a new CCG client. cfg.TokenCache must be set.
func New(cfg Config, log *logger.Log) (*Client, error) {
	if cfg.TokenCache == nil {
		return nil, fmt.Errorf("%s: TokenCache is required", cfg.Name)
	}
	accept := cfg.Accept
	if accept == "" {
		accept = "application/json"
	}
	return &Client{
		baseURL:      cfg.BaseURL,
		accept:       accept,
		name:         cfg.Name,
		httpClient:   &http.Client{Timeout: cfg.Timeout},
		log:          log.New(cfg.Name),
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scopes:       cfg.Scopes,
		tokenCache:   cfg.TokenCache,
	}, nil
}

// tokenResponse is the OAuth 2.0 token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

const cacheKey = "access_token"

// ensureToken returns a cached token or refreshes it using CCG.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	if token, ok := c.tokenCache.Get(ctx, cacheKey); ok {
		return token, nil
	}

	// Single-flight the refresh so concurrent callers issue at most one
	// client-credentials request on a cold/expired cache. The recheck inside
	// covers a token stored between the miss above and the critical section.
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
		return "", fmt.Errorf("%s: create token request: %w", c.name, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: token request failed: %w", c.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Limit error body to 2 MB to prevent OOM from a malicious/misconfigured server.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return "", fmt.Errorf("%s: token request returned %d (failed to read body: %w)", c.name, resp.StatusCode, err)
		}
		return "", fmt.Errorf("%s: token request returned %d: %s", c.name, resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("%s: decode token response: %w", c.name, err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("%s: token response contained empty access_token", c.name)
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	// Subtract 30s buffer so we refresh before actual expiry.
	if ttl > 30*time.Second {
		ttl -= 30 * time.Second
	}
	if ttl > 0 {
		c.tokenCache.SetWithTTL(ctx, cacheKey, tokenResp.AccessToken, ttl)
	} else {
		// No expires_in: use the cache default.
		c.tokenCache.Set(ctx, cacheKey, tokenResp.AccessToken)
	}

	c.log.Info("OAuth 2.0 token obtained", "expires_in", tokenResp.ExpiresIn)
	return tokenResp.AccessToken, nil
}

// Get performs an authenticated GET to baseURL+path and returns the body,
// which is limited to 10 MB.
func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
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
		return nil, fmt.Errorf("%s: create request: %w", c.name, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", c.accept)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", c.name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", c.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: GET %s returned %d: %s", c.name, path, resp.StatusCode, string(body))
	}
	return body, nil
}
