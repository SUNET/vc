// Package statusserviceclient is an issuer-side client for an external
// status-list service implementing draft-ietf-oauth-status-list-21 (Token
// Status List) - concretely, github.com/sirosfoundation/siros-status-service,
// though nothing here is specific to that implementation beyond matching its
// wire protocol.
//
// The service is reached through two HTTP endpoints:
//
//   - An OAuth2 Authorization Server's POST /token, authenticated with an
//     RFC 7523 self-signed client assertion: no separate registration step
//     exists, the assertion's embedded `jwk` header (RFC 7515 §4.1.3) IS the
//     proof of identity, verified against the signature the assertion
//     itself carries.
//   - An issuer-facing ingestion API: POST /allocate reserves a fresh
//     (list_url, index) pair; PATCH /status/{listID}/{idx} updates one
//     already allocated to this issuer's identity.
//
// # Pool design (requirement: "pool-based")
//
// Allocate is never called synchronously on the credential-issuance hot
// path. A background goroutine keeps a local pool of Config.PoolSize
// pre-allocated entries topped up; Take pops one immediately in the common
// case. When the pool runs dry, Take falls back to one bounded, retried
// synchronous allocation rather than failing immediately - this is what
// makes a cold start (empty pool right after process start) still work
// without every early credential going straight to degraded mode.
//
// Low-water-mark refill: the background loop wakes whenever the pool drops
// to or below Config.LowWaterMark and tops it back up to Config.PoolSize,
// plus a periodic check so a refill that failed outright (service down) is
// retried later even with no Take calls draining the pool further.
//
// # Ownership and revocation
//
// The status service enforces ownership of an index by issuer identity (the
// `iss`/`sub` in the RFC 7523 client assertion, i.e. Config.IssuerID) at
// PATCH /status time, not by which process or pool instance originally
// allocated it. Every replica of a given issuer deployment shares the same
// IssuerID and signing key (Config.Key, defaulting to the credential-signing
// key), so any replica holding a valid access token can revoke any index
// this issuer identity has ever been given - regardless of which replica's
// pool drew it out originally. SetStatus therefore takes a list ID and index
// directly (as recorded against the issued credential) and needs no pool
// bookkeeping at all; there is no "which replica owns this allocation"
// problem to solve.
//
// # Restart durability
//
// The pool is pure in-memory and best-effort. A process restart loses
// whatever was pre-allocated and not yet handed to a credential: those
// specific indices are left sitting VALID in the remote service forever,
// referenced by nothing. That is wasted capacity - at most PoolSize entries
// against a status list whose capacity is ordinarily many orders of
// magnitude larger - never a correctness or security issue, since no
// credential ever carries one of those indices. This mirrors this
// repository's own existing tolerance for the identical shape of problem in
// internal/issuer/apiv1/handlers_bbs.go's invalidateStatusEntry (a status
// entry allocated for a credential that then fails to issue is left VALID
// and unreferenced rather than reclaimed). Persisting pool state across
// restarts was judged not worth the added complexity - a datastore, a
// recovery path, cross-process coordination - for a loss this small and
// this harmless.
//
// # Retry and degraded mode (requirement: "recover from intermittent errors")
//
// Every call this package makes to the status service (/token, /allocate,
// /status) retries transient failures - network errors and 5xx responses -
// with exponential backoff and jitter, matching this repository's existing
// hand-rolled backoff idiom (see internal/apigw/apiv1/sign_metadata.go)
// rather than adding a backoff library dependency solely for this. 4xx
// responses (bad request, unauthorized, forbidden, not found, gone) are
// treated as permanent - retrying an ownership or validation failure cannot
// make it succeed - and are returned immediately.
//
// The background refill loop retries indefinitely (bounded only by backoff
// growth, capped at maxBackoff) since a status-service outage is expected to
// be temporary and there is no caller waiting on it. Take's synchronous
// fallback, in contrast, is bounded by takeFallbackTimeout so a request
// blocked on it fails (or degrades, per the caller's chosen DegradedMode)
// within a bounded time instead of hanging a credential-issuance request
// indefinitely on a service that may simply be down. What happens when even
// that bounded fallback fails is Config.DegradedMode's decision, applied by
// the caller (see model.StatusServiceConfig.DegradedMode) - this package
// only reports ErrPoolExhausted and lets the caller decide.
package statusserviceclient

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
)

// Status is a draft-ietf-oauth-status-list-21 status value, as accepted by
// PATCH /status/{listID}/{idx}.
type Status string

const (
	StatusValid     Status = "VALID"
	StatusInvalid   Status = "INVALID"
	StatusSuspended Status = "SUSPENDED"
)

// Config configures a Client. IngestionURL, ASURL, IssuerID and Key are
// required; everything else has a workable default.
type Config struct {
	// IngestionURL is the base URL of the status service's ingestion API
	// (no trailing slash required).
	IngestionURL string
	// ASURL is the base URL of the status service's Authorization Server.
	ASURL string
	// IssuerID is this issuer's self-asserted identity (RFC 7523 iss/sub).
	IssuerID string
	// Key signs the RFC 7523 client assertion. Must be a P-256 key: the
	// status service's AS verifies an ES256 signature.
	Key *ecdsa.PrivateKey
	// PoolSize is the target number of pre-allocated entries. Defaults to
	// 50 when zero.
	PoolSize int
	// LowWaterMark triggers a refill once the pool drops to or below this
	// many entries. Defaults to PoolSize/4 (minimum 5) when zero.
	LowWaterMark int
	// AllocateExpiry, when non-zero, is sent as POST /allocate's `exp`
	// (time.Now().Add(AllocateExpiry)). Zero omits `exp`, asking the
	// status service for its own configured maximum lifetime - see this
	// package's doc comment and model.StatusServiceConfig.AllocateExpiry
	// for why that is the right default for pool entries specifically.
	AllocateExpiry time.Duration

	// HTTPClient, when set, replaces the default *http.Client (used by
	// tests to point at an httptest.Server with a short timeout).
	HTTPClient *http.Client

	// The following bound retry/backoff behaviour. All default to sensible
	// production values when zero; tests override them to keep runs fast.
	//
	// RetryInitialBackoff is the first retry delay's upper bound (actual
	// sleep is uniform-random in [0, current backoff) - full jitter, to
	// avoid every replica of a multi-instance issuer retrying in lockstep
	// against a recovering status service).
	RetryInitialBackoff time.Duration
	// RetryMaxBackoff caps how large the backoff is allowed to grow.
	RetryMaxBackoff time.Duration
	// TakeFallbackTimeout bounds Take's synchronous allocation attempt
	// when the pool is empty.
	TakeFallbackTimeout time.Duration
	// RefillInterval is the periodic-check period for the background
	// refill loop, independent of low-water-mark wakeups.
	RefillInterval time.Duration
}

const (
	defaultPoolSize            = 50
	defaultLowWaterMarkMin     = 5
	defaultRetryInitialBackoff = 250 * time.Millisecond
	defaultRetryMaxBackoff     = 30 * time.Second
	defaultTakeFallbackTimeout = 5 * time.Second
	defaultRefillInterval      = 30 * time.Second
	defaultHTTPTimeout         = 10 * time.Second
	// assertionLifetime is how long a client assertion is valid for once
	// signed - short, per RFC 7523 guidance and to match
	// siros-status-service's own reference client (tools/loadtest/identity.go).
	assertionLifetime = time.Minute
	// tokenRefreshSkew renews the cached access token this long before it
	// actually expires, so a token never expires mid-flight inside a
	// request that already started using it.
	tokenRefreshSkew = 30 * time.Second
)

// ErrPoolExhausted is returned by Take when the pool is empty and the
// bounded synchronous fallback allocation also failed.
var ErrPoolExhausted = fmt.Errorf("statusserviceclient: pool exhausted and fallback allocation failed")

// Client talks to one external status-list service on behalf of one issuer
// identity, keeping a background-refilled pool of pre-allocated entries.
type Client struct {
	cfg  Config
	http *http.Client
	log  *logger.Log

	tokenMu  sync.Mutex
	token    string
	tokenExp time.Time

	pool *pool

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a Client and starts its background pool-refill goroutine. It
// does not block on an initial fill: if the status service is unreachable
// at startup, the pool simply starts empty and Take's synchronous fallback
// (or DegradedMode, if that also fails) covers the gap until the background
// loop catches up - consistent with this issuer's own credential-issuance
// path never being made to wait on this service's availability.
func New(cfg Config, log *logger.Log) (*Client, error) {
	if cfg.IngestionURL == "" {
		return nil, fmt.Errorf("statusserviceclient: IngestionURL is required")
	}
	if cfg.ASURL == "" {
		return nil, fmt.Errorf("statusserviceclient: ASURL is required")
	}
	if cfg.IssuerID == "" {
		return nil, fmt.Errorf("statusserviceclient: IssuerID is required")
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("statusserviceclient: Key is required")
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = defaultPoolSize
	}
	if cfg.LowWaterMark <= 0 {
		cfg.LowWaterMark = cfg.PoolSize / 4
		if cfg.LowWaterMark < defaultLowWaterMarkMin {
			cfg.LowWaterMark = defaultLowWaterMarkMin
		}
		if cfg.LowWaterMark >= cfg.PoolSize {
			cfg.LowWaterMark = cfg.PoolSize - 1
		}
	}
	if cfg.RetryInitialBackoff <= 0 {
		cfg.RetryInitialBackoff = defaultRetryInitialBackoff
	}
	if cfg.RetryMaxBackoff <= 0 {
		cfg.RetryMaxBackoff = defaultRetryMaxBackoff
	}
	if cfg.TakeFallbackTimeout <= 0 {
		cfg.TakeFallbackTimeout = defaultTakeFallbackTimeout
	}
	if cfg.RefillInterval <= 0 {
		cfg.RefillInterval = defaultRefillInterval
	}
	if log == nil {
		log = logger.NewSimple("statusserviceclient")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	c := &Client{
		cfg:    cfg,
		http:   httpClient,
		log:    log.New("statusserviceclient"),
		stopCh: make(chan struct{}),
	}
	c.pool = newPool(c)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.pool.run(c.stopCh)
	}()

	return c, nil
}

// PoolSize returns the configured target pool size (after defaulting).
func (c *Client) PoolSize() int { return c.cfg.PoolSize }

// LowWaterMark returns the configured refill trigger (after defaulting).
func (c *Client) LowWaterMark() int { return c.cfg.LowWaterMark }

// PoolLen returns the pool's current size. For observability and tests.
func (c *Client) PoolLen() int { return c.pool.size() }

// Close stops the background refill goroutine. Safe to call more than once.
func (c *Client) Close() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.wg.Wait()
}

// retryConfig returns the retry parameters for on-demand (foreground) calls
// - Take's synchronous fallback and SetStatus - which must eventually give
// up so they don't block a caller forever.
func (c *Client) foregroundRetry() retryConfig {
	return retryConfig{
		initialBackoff: c.cfg.RetryInitialBackoff,
		maxBackoff:     c.cfg.RetryMaxBackoff,
		maxElapsed:     c.cfg.TakeFallbackTimeout,
	}
}

// backgroundRetry returns the retry parameters for the pool's own refill
// loop: unbounded attempts and unbounded elapsed time (retry forever, with
// backoff capped at RetryMaxBackoff) since nothing is waiting on any single
// refill attempt - only ctx cancellation (Close) stops it.
func (c *Client) backgroundRetry() retryConfig {
	return retryConfig{
		initialBackoff: c.cfg.RetryInitialBackoff,
		maxBackoff:     c.cfg.RetryMaxBackoff,
	}
}
