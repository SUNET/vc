package statusserviceclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// classifyStatus turns an HTTP status code into either nil (2xx), a
// permanent error (4xx - retrying cannot help: bad request, unauthorized,
// forbidden, not found, gone), or a plain (retryable) error (5xx, or
// anything else unexpected).
// classifyResourceStatus is classifyStatus for calls made with a CACHED
// access token.
//
// A 401 there is not the service saying "no" - it is the cached token being
// stale, which is the one 4xx worth another attempt: the token has just been
// cleared, so the retry fetches a fresh one and asks again. Classifying it
// permanent (as a bare classifyStatus does) stops the retry loop dead and
// turns a routine token expiry into a failed allocation.
//
// Token-endpoint responses keep using classifyStatus: a 4xx there really is
// a refusal, and retrying it would hammer the AS with credentials it has
// already rejected.
func classifyResourceStatus(statusCode int, body []byte) error {
	if statusCode == http.StatusUnauthorized {
		return fmt.Errorf("status service returned 401 for a cached token: %s",
			strings.TrimSpace(string(body)))
	}
	return classifyStatus(statusCode, body)
}

func classifyStatus(statusCode int, body []byte) error {
	if statusCode >= 200 && statusCode < 300 {
		return nil
	}
	msg := fmt.Sprintf("status service returned %d: %s", statusCode, strings.TrimSpace(string(body)))
	if statusCode >= 400 && statusCode < 500 {
		return permanent(fmt.Errorf("%s", msg))
	}
	return fmt.Errorf("%s", msg)
}

// getToken returns a valid access token, using the cached one if it has
// more than tokenRefreshSkew left, and otherwise fetching (and retrying) a
// fresh one. Safe for concurrent use.
func (c *Client) getToken(ctx context.Context) (string, error) {
	if token, ok := c.cachedToken(); ok {
		return token, nil
	}

	// Only one caller fetches; the rest wait for it. Crucially they wait on
	// ctx too, so a foreground Take or SetStatus still honours its own
	// deadline instead of being pinned behind someone else's retrying token
	// exchange - holding tokenMu across the whole fetch made
	// TakeFallbackTimeout unenforceable, since a mutex wait cannot be
	// cancelled.
	select {
	case c.tokenFetch <- struct{}{}:
		defer func() { <-c.tokenFetch }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// The winner of a previous race may have just stored one.
	if token, ok := c.cachedToken(); ok {
		return token, nil
	}

	var token string
	var expiresIn int64
	err := retry(ctx, c.foregroundRetry(), func(ctx context.Context) error {
		t, exp, err := c.fetchToken(ctx)
		if err != nil {
			return err
		}
		token, expiresIn = t, exp
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("fetch access token: %w", err)
	}

	c.tokenMu.Lock()
	c.token = token
	c.tokenExp = time.Now().Add(time.Duration(expiresIn) * time.Second)
	c.tokenMu.Unlock()

	return token, nil
}

// cachedToken returns the cached access token when it has more than
// tokenRefreshSkew left. The lock is held only across these few lines, never
// across a network call.
func (c *Client) cachedToken() (string, bool) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.token != "" && time.Until(c.tokenExp) > tokenRefreshSkew {
		return c.token, true
	}
	return "", false
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// fetchToken performs a single (non-retried) token request. Matches
// siros-status-service's internal/as handleToken: form-encoded, not JSON.
func (c *Client) fetchToken(ctx context.Context) (string, int64, error) {
	tokenURL := strings.TrimRight(c.cfg.ASURL, "/") + "/token"

	assertion, err := buildAssertion(ctx, c.cfg.IssuerID, c.cfg.Signer, tokenURL)
	if err != nil {
		return "", 0, permanent(err) // a signing failure will not fix itself by retrying
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, permanent(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, err // network error: retryable
	}
	defer func() { _ = resp.Body.Close() }()

	// Not discarded: a connection dropped after the headers, or mid-body,
	// is a transient network failure. Swallowing it here turns it into a
	// JSON decode error below, which is marked permanent and stops the
	// retry loop - the one case the loop exists for.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("read token response: %w", err)
	}
	if err := classifyStatus(resp.StatusCode, body); err != nil {
		return "", 0, err
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, permanent(fmt.Errorf("decode token response: %w", err))
	}
	if tr.AccessToken == "" {
		return "", 0, permanent(fmt.Errorf("token response carried no access_token"))
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 3600
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}

type allocateRequest struct {
	Exp *time.Time `json:"exp,omitempty"`
}

type allocateResponse struct {
	ListURL string    `json:"list_url"`
	Index   uint64    `json:"index"`
	Exp     time.Time `json:"exp"`
}

// allocateOnce performs a single (non-retried) POST /allocate call.
func (c *Client) allocateOnce(ctx context.Context) (Entry, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return Entry{}, err
	}

	var body []byte
	if c.cfg.AllocateExpiry > 0 {
		exp := time.Now().Add(c.cfg.AllocateExpiry)
		body, err = json.Marshal(allocateRequest{Exp: &exp})
		if err != nil {
			return Entry{}, permanent(err)
		}
	} else {
		body = []byte("{}")
	}

	allocateURL := strings.TrimRight(c.cfg.IngestionURL, "/") + "/allocate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, allocateURL, bytes.NewReader(body))
	if err != nil {
		return Entry{}, permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// As in fetchToken: a truncated response is retryable, and discarding
	// the read error would disguise it as a permanent decode failure.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Entry{}, fmt.Errorf("read allocate response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The cached token may have been rejected (e.g. the AS restarted
		// its trust store, or the token expired right at the skew
		// boundary). Drop it so the next attempt fetches a fresh one
		// instead of retrying with the same token forever.
		c.tokenMu.Lock()
		c.token = ""
		c.tokenMu.Unlock()
	}
	if err := classifyResourceStatus(resp.StatusCode, respBody); err != nil {
		return Entry{}, err
	}

	var ar allocateResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return Entry{}, permanent(fmt.Errorf("decode allocate response: %w", err))
	}
	if ar.ListURL == "" {
		return Entry{}, permanent(fmt.Errorf("allocate response carried no list_url"))
	}

	listID, err := ListIDFromURL(ar.ListURL)
	if err != nil {
		return Entry{}, permanent(fmt.Errorf("allocate response list_url %q: %w", ar.ListURL, err))
	}

	return Entry{ListURL: ar.ListURL, ListID: listID, Index: ar.Index, Exp: ar.Exp}, nil
}

// ListIDFromURL extracts the list ID (the final path segment) from a
// list_url such as "https://status.example.org/lists/<id>", for use in the
// PATCH /status/{listID}/{idx} path - the allocate response does not return
// the ID separately, only the full verifier-facing URL.
//
// The same value is what goes into a credential's `status.status_list.uri`,
// so this validates the whole URL rather than just reaching for the last
// segment. Anything a verifier could not resolve has to be rejected here:
// deriving a usable list ID from an unusable URL is the bad outcome, because
// the client would then happily PATCH the right entry while the credential
// carries a reference nobody can follow.
func ListIDFromURL(listURL string) (string, error) {
	u, err := url.Parse(listURL)
	if err != nil {
		return "", err
	}

	// Absolute, with a host: the contract is a verifier-facing URL, and a
	// relative value like "lists/abc" (or bare "abc") would yield a
	// perfectly good-looking list ID from something no verifier can fetch.
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("list URL %q is not absolute: a verifier-facing scheme and host are required", listURL)
	}

	// A trailing slash has to be rejected rather than trimmed: path.Base
	// turns "/lists/" into "lists", so a malformed list_url would silently
	// yield the collection name as a list ID and SetStatus would go on to
	// PATCH the wrong resource.
	if strings.HasSuffix(u.Path, "/") {
		return "", fmt.Errorf("list URL path %q ends in a slash, so it names no list", u.Path)
	}

	id := path.Base(u.Path)
	if id == "" || id == "." || id == "/" {
		return "", fmt.Errorf("could not determine list ID from path %q", u.Path)
	}
	return id, nil
}

type setStatusRequest struct {
	Status string `json:"status"`
}

// setStatusOnce performs a single (non-retried) PATCH /status/{listID}/{idx}
// call.
func (c *Client) setStatusOnce(ctx context.Context, listID string, idx uint64, status Status) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	body, err := json.Marshal(setStatusRequest{Status: string(status)})
	if err != nil {
		return permanent(err)
	}

	statusURL := fmt.Sprintf("%s/status/%s/%d", strings.TrimRight(c.cfg.IngestionURL, "/"), url.PathEscape(listID), idx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, statusURL, bytes.NewReader(body))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// A truncated response here only costs the error message its detail,
	// but propagate it anyway rather than reporting a misleading status.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read status response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.tokenMu.Lock()
		c.token = ""
		c.tokenMu.Unlock()
	}
	return classifyResourceStatus(resp.StatusCode, respBody)
}

// SetStatus updates the status of a previously allocated index, retrying
// transient failures (network errors, 5xx) with backoff bounded by
// TakeFallbackTimeout. A permanent failure (the status service's answer to
// "no", such as 403 not-owner, 404 not-found, or 410 archived) is returned
// immediately, unretried.
func (c *Client) SetStatus(ctx context.Context, listID string, idx uint64, status Status) error {
	return retry(ctx, c.foregroundRetry(), func(ctx context.Context) error {
		return c.setStatusOnce(ctx, listID, idx, status)
	})
}
