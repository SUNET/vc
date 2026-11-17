package statusserviceclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// classifyResourceStatus is classifyStatus for calls made with a CACHED
// access token.
//
// A 401 there is not the service saying "no" - it is the cached token being
// stale, which is the one 4xx worth another attempt: the token has just been
// cleared, so the retry fetches a fresh one and asks again. Classifying it
// permanent (as a bare classifyStatus does) stops the retry loop dead and
// turns a routine token expiry into a failed allocation.
//
// Token-endpoint responses keep using classifyStatus, where a 4xx is a
// refusal and is not retried - retrying would re-present credentials the AS
// has already rejected. The exceptions classifyStatus makes for 408 and 429
// apply there too, and are not that: a rate-limited or timed-out AS has not
// rejected anything, and the backoff governs when the next attempt goes
// out, so it is asking again rather than hammering.
func classifyResourceStatus(statusCode int, body []byte) error {
	if statusCode == http.StatusUnauthorized {
		return fmt.Errorf("status service returned 401 for a cached token: %s",
			strings.TrimSpace(string(body)))
	}
	return classifyStatus(statusCode, body)
}

// classifyAllocateStatus is classifyResourceStatus for POST /allocate,
// which is the one call in this package that is NOT idempotent.
//
// The service reserves and records the index before it writes the
// response, and the request carries no idempotency key, so a retry after
// an ambiguous outcome does not re-ask for the same slot - it asks for
// another one. The reply that was lost named a slot nothing will ever
// reference, and nothing on either side can reconcile it later. Repeating
// that on every transient 5xx leaks entries without bound, which is the
// one way this pool could actually consume a list's capacity.
//
// So the rule here is narrower than the generic one: retry only outcomes
// that PROVE no index was reserved.
//
//   - 401 proves it: the request was rejected at authentication, before any
//     handler ran. The cached token has just been cleared, so a retry
//     fetches a fresh one - this is routine token expiry, not a refusal.
//   - Other 4xx are refusals; nothing was allocated, and retrying the same
//     request cannot help either. Permanent, as before.
//   - 5xx and anything unexpected are AMBIGUOUS. The service may have
//     reserved the index and then failed on the way out. Those stop the
//     loop now, where the generic rule retried them.
//
// Losing one slot to an ambiguous failure is unavoidable without a
// protocol change (an idempotency key, or a reconciliation endpoint). The
// bound is what this restores: at most one per allocation attempt, instead
// of one per retry.
func classifyAllocateStatus(statusCode int, body []byte) error {
	if statusCode == http.StatusUnauthorized {
		return classifyResourceStatus(statusCode, body)
	}
	err := classifyStatus(statusCode, body)
	if err == nil || isPermanent(err) {
		return err
	}
	return permanent(fmt.Errorf("%w (not retried: POST /allocate is not idempotent and may already have reserved an index)", err))
}

// allocateDispatchIsRetryable reports whether an error from
// http.Client.Do on the allocate POST proves the request never reached the
// service.
//
// Only two shapes do, and both fail before a single byte of the request is
// written: the name did not resolve, and the connection could not be
// established. Everything else - a reset after the write, a read deadline,
// a half-closed connection, a proxy giving up - is indistinguishable from
// "the service allocated and the response was lost", so it is treated as
// the latter. That is the direction this has to fail in: a wrong "safe to
// retry" silently burns list capacity, while a wrong "ambiguous" costs one
// allocation attempt that the next refill tick repeats anyway.
func allocateDispatchIsRetryable(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// classifyStatus turns an HTTP status code into either nil (2xx), a
// permanent error (most 4xx - retrying cannot help: bad request,
// unauthorized, forbidden, not found, gone), or a plain (retryable) error
// (5xx, 408, 429, or anything else unexpected).
//
// 408 and 429 are 4xx that explicitly mean "ask again". Treating 429 as a
// refusal is the costly one: a rate-limited status service would fail the
// allocation outright, and an issuer running the default degraded mode
// then mints a credential with no status claim - unrevokable - because
// the service asked it to slow down.
//
// The backoff already in retry() governs when the next attempt goes out.
// Retry-After is deliberately not read: honouring a server-chosen delay
// would let the service pin a foreground Take past its own
// TakeFallbackTimeout, which is the bound that keeps issuance from
// hanging.
func classifyStatus(statusCode int, body []byte) error {
	if statusCode >= 200 && statusCode < 300 {
		return nil
	}
	msg := fmt.Sprintf("status service returned %d: %s", statusCode, strings.TrimSpace(string(body)))
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return fmt.Errorf("%s", msg)
	}
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
		if allocateDispatchIsRetryable(err) {
			return Entry{}, err
		}
		// The request was on the wire. Whether the service reserved an
		// index before this failed is unknowable from here, so it is
		// assumed to have done: see classifyAllocateStatus.
		c.log.Error(err, "allocate request failed after it was sent; a status list index may have been reserved and will stay VALID and unreferenced, and this attempt is not retried because retrying would reserve another")
		return Entry{}, permanent(fmt.Errorf("allocate request failed after it was sent, so an index may already have been reserved: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	// Unlike fetchToken, a truncated response here is NOT retryable: the
	// service writes the response after it has committed the reservation,
	// so a body that stops halfway is the strongest evidence there is that
	// an index was allocated and its identity lost.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.log.Error(err, "allocate response was truncated; the reserved index is lost and will stay VALID and unreferenced")
		return Entry{}, permanent(fmt.Errorf("read allocate response (an index was probably reserved and its identity lost): %w", err))
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
	if err := classifyAllocateStatus(resp.StatusCode, respBody); err != nil {
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
		return Entry{}, permanent(fmt.Errorf("allocate response list_url %q: %w", redactURL(ar.ListURL), err))
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

	// Absolute, with a host, over http(s): the contract is a verifier-facing
	// URL, and anything else yields a perfectly good-looking list ID from
	// something no verifier will fetch. A relative value like "lists/abc"
	// (or a bare "abc") has no origin at all, and a non-HTTP scheme is
	// refused outright by the resolver on the other side - see
	// pkg/revocation's StatusListChecker, which rejects any scheme but
	// http and https to limit SSRF surface. Accepting one here would mint
	// credentials whose status reference that checker will not follow.
	if u.Host == "" {
		return "", fmt.Errorf("list URL %q is not absolute: a verifier-facing scheme and host are required", listURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("list URL %q uses scheme %q: a status list must be fetchable over http or https", listURL, u.Scheme)
	}

	// A fragment is never sent in an HTTP request, so a list_url carrying
	// one names a different string than the one that will be fetched. The
	// credential would carry - and bind its status token's sub to -
	// ".../list#anything" while every verifier fetches ".../list", so the
	// Section 8.3 subject check fails and the reference is unusable. There
	// is no reading under which a fragment belongs in a status list URL,
	// so it is refused rather than stripped.
	if u.Fragment != "" || strings.Contains(listURL, "#") {
		return "", fmt.Errorf("list URL %q carries a fragment, which is never sent in the request that fetches it", listURL)
	}

	// This URL is PUBLISHED. It becomes the credential's
	// status.status_list.uri, which every holder keeps and every verifier
	// fetches, so credentials in it would be handed to everyone the
	// credential reaches - and the section 8.3 subject check would be
	// comparing against a string containing a password. A verifier fetches
	// it with no credentials at all, so userinfo cannot be doing any work
	// here either.
	//
	// The message does not echo the URL: refusing it must not be the thing
	// that copies the secret into the log.
	if u.User != nil {
		return "", fmt.Errorf("list URL for host %q carries credentials, and this URL is published in every credential issued against the list", u.Host)
	}

	// A trailing slash has to be rejected rather than trimmed: path.Base
	// turns "/lists/" into "lists", so a malformed list_url would silently
	// yield the collection name as a list ID and SetStatus would go on to
	// PATCH the wrong resource.
	if strings.HasSuffix(u.Path, "/") {
		return "", fmt.Errorf("list URL path %q ends in a slash, so it names no list", u.Path)
	}

	// A dot segment anywhere in the path makes this URL name one resource
	// and resolve to another, which is the failure this whole function
	// exists to prevent - and here it happens in both directions at once.
	//
	// As the LAST segment it becomes the list ID. "/lists/%2e%2e" parses
	// to the path "/lists/..", path.Base returns "..", and url.PathEscape
	// leaves it alone because a dot is unreserved - so the PATCH goes out
	// with the literal request-URI "/status/../5". Go does not remove dot
	// segments from a request URI; whatever is in front of the ingestion
	// service does, and the write lands on "/5".
	//
	// EARLIER in the path it is quieter and no better. "/lists/../admin/abc"
	// yields the list ID "abc" and a PATCH that looks entirely right, while
	// the credential carries a status_list.uri that a verifier resolves to
	// "/admin/abc" - a different resource than the one just written, with
	// the status token's sub bound to the un-normalised string either way.
	//
	// No status list URL needs one, so both are refused rather than
	// normalised away: normalising would mint a credential carrying a URL
	// the issuer never saw.
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("list URL path %q contains the dot segment %q, which names one resource and resolves to another", u.Path, segment)
		}
	}

	// The ESCAPED path, not u.Path. u.Path is already percent-decoded, so
	// "/lists/a%2Fb" reads as "/lists/a/b" and path.Base hands back "b" -
	// the last segment of a list ID, not the list ID. The credential would
	// then carry a status_list.uri a verifier resolves to the list "a/b"
	// while every PATCH went to a list called "b": status updates landing
	// on the wrong list, silently, for the life of the credential.
	escaped := path.Base(u.EscapedPath())
	id, err := url.PathUnescape(escaped)
	if err != nil {
		return "", fmt.Errorf("list URL path %q has an unusable last segment: %w", u.EscapedPath(), err)
	}

	// And the segment has to be one this client can reproduce. Every PATCH
	// is built with url.PathEscape(id), so an id whose escaping differs
	// from what the service sent addresses something else: "%41%42" decodes
	// to "AB" and re-escapes to "AB", a different request-URI than the one
	// the allocate response named.
	//
	// Refused rather than passed through verbatim, for the same reason the
	// rest of this function refuses: a list ID that cannot be round-tripped
	// is one this client cannot reliably address, and guessing is how a
	// credential ends up pointing somewhere nobody intended.
	if url.PathEscape(id) != escaped {
		return "", fmt.Errorf("list URL's last segment %q is encoded in a form this client cannot reproduce (it re-escapes to %q)", escaped, url.PathEscape(id))
	}

	if id == "" || id == "/" {
		return "", fmt.Errorf("could not determine list ID from path %q", u.Path)
	}
	// The same rule SetStatus applies to a caller-supplied ID, so an ID
	// derived here cannot be one SetStatus would then refuse.
	if err := requireUsableListID(id); err != nil {
		return "", fmt.Errorf("list URL %q names no usable list: %w", listURL, err)
	}
	return id, nil
}

type setStatusRequest struct {
	Status string `json:"status"`
}

// setStatusOnce performs a single (non-retried) PATCH /status/{listID}/{idx}
// call.
func (c *Client) setStatusOnce(ctx context.Context, listID string, idx uint64, status Status) error {
	// SetStatus is exported and takes the ID directly, so this does not
	// rely on ListIDFromURL having vetted it. url.PathEscape covers a
	// separator - a "/" becomes %2F - but not a dot segment, which is
	// unreserved and passes through to be resolved away by whatever sits
	// in front of the service. Refused rather than escaped, because there
	// is no escaping that makes "." mean a list.
	if listID == "" || listID == "." || listID == ".." {
		return permanent(fmt.Errorf("list ID %q names no list: a dot segment would send this PATCH to a different path", listID))
	}

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
// transient failures (network errors, 5xx, 408, 429) with backoff bounded
// by TakeFallbackTimeout. A permanent failure (the status service's answer
// to "no", such as 403 not-owner, 404 not-found, or 410 archived) is
// returned immediately, unretried.
//
// listID is checked before it is put in a path: this is a public entry
// point, and the caller's value usually comes back out of the caller's own
// storage rather than from the Entry this package handed it.
func (c *Client) SetStatus(ctx context.Context, listID string, idx uint64, status Status) error {
	if err := requireUsableListID(listID); err != nil {
		return permanent(err)
	}
	return retry(ctx, c.foregroundRetry(), func(ctx context.Context) error {
		return c.setStatusOnce(ctx, listID, idx, status)
	})
}

// requireUsableListID refuses a list ID that would not stay one segment of
// the PATCH path.
//
// url.PathEscape does NOT escape a dot, because a dot is unreserved - so
// ".." passes through intact and the request-URI becomes "/status/../5".
// Go does not remove dot segments from a request URI; whatever sits in
// front of the ingestion service does, and the write lands on "/5". That is
// the same traversal ListIDFromURL refuses when DERIVING an ID, and it has
// to be refused here too, because SetStatus is reached with an ID the
// caller stored rather than one this package just produced.
//
// A slash is refused as well. Every ID this package produces comes out of
// path.Base and cannot contain one, so a caller passing "lists/abc" has
// passed a path by mistake; escaped to "lists%2Fabc" it would silently
// address a list nobody has.
func requireUsableListID(listID string) error {
	switch {
	case listID == "":
		return errors.New("statusserviceclient: a list ID is required")
	case listID == "." || listID == "..":
		return fmt.Errorf("statusserviceclient: list ID %q is a dot segment, which resolves to a different resource than it names", listID)
	case strings.Contains(listID, "/"):
		return fmt.Errorf("statusserviceclient: list ID %q contains a slash, so it is a path rather than a list ID", listID)
	}
	// A control character - a NUL most of all - is never part of a real
	// list ID, and "/lists/abc%00" decodes to one. url.PathEscape encodes
	// it rather than refusing, so without this it would travel.
	for _, r := range listID {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("statusserviceclient: list ID %q contains a control character", listID)
		}
	}
	return nil
}
