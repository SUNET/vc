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
// IssuerID and signing key (Config.Signer, which this package requires and
// does not default), so any replica holding a valid access token can revoke any index
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
// credential ever carries one of those indices. An ambiguous /allocate
// outcome strands entries the same way and is counted the same way: see
// the retry section below for why each one costs at most a single slot. This mirrors this
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
// POST /allocate is the exception, because it is the only call here that
// is not idempotent: the service reserves and records the index before it
// writes the response, and the request carries no idempotency key. A retry
// after an outcome the client cannot interpret does not re-ask for the
// same slot, it asks for a second one - and the slot named by the lost
// reply is then VALID, referenced by nothing, and unreconcilable from
// either side. So /allocate retries only outcomes that PROVE nothing was
// reserved: a name that did not resolve, a connection that was never
// established, and a 401 (rejected at authentication, before any handler
// ran - routine cached-token expiry). A 5xx, a truncated response body, or
// any transport failure after the request was written stops the attempt
// where the generic rule retried it. See classifyAllocateStatus.
//
// Closing it properly needs a protocol change - an idempotency key on
// /allocate, or an endpoint to reconcile reservations an issuer never
// acknowledged - which is a change to the status service, not to this
// client. What this client can do, and does, is bound the loss at one slot
// per allocation attempt instead of one per retry.
//
// The background refill loop retries indefinitely (bounded only by backoff
// growth, capped at maxBackoff) since a status-service outage is expected to
// be temporary and there is no caller waiting on it. Take's synchronous
// fallback, in contrast, is bounded by takeFallbackTimeout so a request
// blocked on it fails (or degrades, per the caller's chosen DegradedMode)
// within a bounded time instead of hanging a credential-issuance request
// indefinitely on a service that may simply be down. What happens when even
// that bounded fallback fails is the CALLER's decision - this package only
// reports ErrPoolExhausted, and the issuer that embeds it chooses between
// issuing a credential with no status claim (unrevokable by this mechanism,
// otherwise perfectly valid) and failing the issuance outright. That choice
// belongs to whoever is issuing, not here: this package has no way to know
// which of availability and revokability that deployment would rather keep.
package statusserviceclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/pki"

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

// Config configures a Client. IngestionURL, ASURL, IssuerID and Signer are
// required; everything else has a workable default.
type Config struct {
	// IngestionURL is the base URL of the status service's ingestion API
	// (no trailing slash required).
	IngestionURL string
	// ASURL is the base URL of the status service's Authorization Server.
	ASURL string
	// IssuerID is this issuer's self-asserted identity (RFC 7523 iss/sub).
	IssuerID string
	// Signer signs the RFC 7523 client assertion. Must sign ES256, which
	// the status service's AS requires and which means a P-256 EC key.
	//
	// A pki.Signer rather than a raw key so the key can live in an HSM: the
	// assertion proves possession by producing a signature, and nothing
	// here ever needs the private half. This is also how the rest of the
	// repository signs JWTs (pkg/jose.MakeJWT).
	Signer pki.Signer
	// PoolSize is the target number of pre-allocated entries. Defaults to
	// 50 when zero.
	PoolSize int
	// LowWaterMark triggers a refill once the pool drops to or below this
	// many entries. Defaults to PoolSize/4 (minimum 5) when zero.
	LowWaterMark int
	// AllocateExpiry, when non-zero, is sent as POST /allocate's `exp`
	// (time.Now().Add(AllocateExpiry)). Zero omits `exp`, asking the
	// status service for its own configured maximum lifetime, which is the
	// right default for POOL entries specifically: an entry is allocated
	// before any credential exists to use it, so at refill time there is no
	// individual credential expiry to pass even if one wanted to.
	//
	// Omission is not a promise that the entry outlives the credential. The
	// service answers with now + its own maximum, fixed at allocation time,
	// and a pooled entry has already been sitting here before any credential
	// uses it. An issuer minting 365-day credentials against a service whose
	// maximum is shorter hands out credentials that outlive their status
	// entry and become uncheckable near the end of their life. Set this to
	// cover the longest credential lifetime plus the pool's lead time
	// wherever the service's maximum is not comfortably larger; entries that
	// come back already inside the expiry skew are refused by Take rather
	// than issued.
	AllocateExpiry time.Duration

	// HTTPClient, when set, replaces the default *http.Client (used by
	// tests to point at an httptest.Server with a short timeout).
	//
	// Redirects: the client this package builds refuses to follow them,
	// because following one leaks the access token or the client
	// assertion to wherever the redirect names (see refuseRedirect). A
	// client supplied here inherits that policy only when it has none of
	// its own - an explicit CheckRedirect is left exactly as the caller
	// set it, including a permissive one, and the caller then owns that
	// decision. Nothing is mutated: the policy is applied to a copy.
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
	// TakeFallbackTimeout bounds every FOREGROUND call - Take's
	// synchronous allocation attempt when the pool is empty, and
	// SetStatus - as the total elapsed time across retries. Named for
	// Take because that is the one whose bound keeps credential issuance
	// from hanging, but SetStatus is held to it too.
	//
	// The pool's own background refill is not bounded by this: nothing
	// waits on any single refill attempt, so it retries until Close.
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

	// entryExpirySkew discards a pooled entry this long before its stated
	// expiry. An entry handed out at the last moment still has to survive
	// being signed into a credential and that credential being used, so
	// "not expired yet" is not the same as "worth issuing".
	entryExpirySkew = 60 * time.Second
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
	// tokenFetch is held by whichever caller is currently fetching a token,
	// so the others wait for that one result instead of stampeding the AS.
	// It is a channel rather than a second mutex because a waiter must be
	// able to give up when its own context expires - see getToken.
	tokenFetch chan struct{}

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
	// Both endpoints are checked for scheme as well as presence. Every
	// request this client makes goes to one of them, so a configuration
	// like "ftp://status.example" would otherwise surface as an obscure
	// transport error on the first allocation - and only once the issuer
	// was already serving. The model tags enforce the same thing for
	// config-driven callers; this covers a direct package caller too.
	if err := requireHTTPEndpoint("IngestionURL", cfg.IngestionURL); err != nil {
		return nil, err
	}
	if err := requireHTTPEndpoint("ASURL", cfg.ASURL); err != nil {
		return nil, err
	}
	if cfg.IssuerID == "" {
		return nil, fmt.Errorf("statusserviceclient: IssuerID is required")
	}
	// An AllocateExpiry at or below the skew can never produce a usable
	// entry: the service answers with now+AllocateExpiry, and expired()
	// discards anything inside entryExpirySkew of now, so EVERY entry is
	// born unusable.
	//
	// That is not a slow failure. Each refill allocates one, finds it
	// unusable, marks it invalid to release it, and gives up until the
	// next cycle - burning one remote index per cycle, for as long as the
	// process runs, while the pool never fills and every issuance goes to
	// degraded mode. The cause is a constant in the configuration, so it
	// is decidable here, once, instead of being discovered one wasted
	// allocation at a time.
	if cfg.AllocateExpiry > 0 && cfg.AllocateExpiry <= entryExpirySkew {
		return nil, fmt.Errorf("statusserviceclient: AllocateExpiry %s is at or below the %s expiry skew, so every allocated entry would be discarded as already expiring; set it well above the skew, or leave it zero to take the service's own maximum",
			cfg.AllocateExpiry, entryExpirySkew)
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("statusserviceclient: Signer is required")
	}
	// Checked here rather than left to the first request: the status
	// service rejects a non-ES256 assertion, a rejection is retried, and a
	// misconfiguration would otherwise surface as a slow loop of 4xx rather
	// than as the configuration error it is.
	if alg := cfg.Signer.Algorithm(); alg != "ES256" {
		return nil, fmt.Errorf("statusserviceclient: Signer must sign ES256 (the status service's client assertions), got %s", alg)
	}
	pub, ok := cfg.Signer.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("statusserviceclient: Signer must hold an EC public key, got %T", cfg.Signer.PublicKey())
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("statusserviceclient: Signer must use the P-256 curve (client assertions are ES256), got %s",
			pub.Curve.Params().Name)
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
		httpClient = &http.Client{Timeout: defaultHTTPTimeout, CheckRedirect: refuseRedirect}
	} else if httpClient.CheckRedirect == nil {
		// A copy, so a caller's client is never mutated under it, and
		// only when the caller expressed no policy of their own.
		withPolicy := *httpClient
		withPolicy.CheckRedirect = refuseRedirect
		httpClient = &withPolicy
	}

	c := &Client{
		tokenFetch: make(chan struct{}, 1),
		cfg:        cfg,
		http:       httpClient,
		log:        log.New("statusserviceclient"),
		stopCh:     make(chan struct{}),
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

// expired reports whether a pooled entry is too close to its expiry to put
// into a credential.
//
// An entry with NO stated expiry is never expired. The status service sets
// `exp` at its discretion and may omit it, in which case Entry.Exp is the
// zero time - and treating that as "expired long ago" would discard every
// entry from such a service, emptying the pool as fast as it refills and
// turning a working deployment into an endless allocate loop.
func (c *Client) expired(e Entry) bool {
	if e.Exp.IsZero() {
		return false
	}
	return time.Now().Add(entryExpirySkew).After(e.Exp)
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

// redactURL renders a URL with any credentials in it replaced by "xxxxx",
// for the error and log messages that name one.
//
// url.URL.Redacted does this, but only for a URL that parses; a string that
// does not is returned as the literal "<unparseable url>" rather than
// printed, since the reason it did not parse may be the secret in it.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable url>"
	}
	return u.Redacted()
}

// refuseRedirect stops the HTTP client following a redirect, because every
// URL this client calls is a configured API endpoint and a redirect away
// from one is either a misconfiguration or an attack.
//
// Following one discloses credentials, which is measured rather than
// assumed - see TestAClientDoesNotFollowARedirect. Go strips the
// Authorization header when the redirect crosses to a different HOST, but:
//
//   - it REPLAYS THE REQUEST BODY on 307 and 308 even then, and the token
//     request's body carries the RFC 7523 client assertion - this issuer's
//     signed identity, handed to whoever the redirect names; and
//   - a different PORT on the same host is not a different host to Go, so
//     a redirect to one carries both the bearer token and the body intact.
//
// The access token and the assertion are the two things this package holds
// that are worth stealing, so neither is allowed to travel somewhere the
// configuration did not name.
func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("statusserviceclient: %s %s redirected to %s, and this client does not follow redirects away from a configured endpoint",
		via[len(via)-1].Method, via[len(via)-1].URL.Redacted(), req.URL.Redacted())
}

// requireHTTPEndpoint rejects a missing endpoint, or one this client cannot
// actually call.
func requireHTTPEndpoint(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("statusserviceclient: %s is required", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("statusserviceclient: %s %q is not a URL: %w", name, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("statusserviceclient: %s %q uses scheme %q, but this client speaks only http and https", name, raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("statusserviceclient: %s %q has no host", name, raw)
	}
	// Credentials in the URL are never what authenticates this client -
	// the token endpoint takes an RFC 7523 client assertion and every
	// other call a bearer token - so userinfo here is at best inert and
	// at worst a password copied into every log line that prints the
	// endpoint. Go would also send it as basic auth on each request,
	// alongside the Authorization header this client sets, which is not
	// what any operator writing it meant.
	if u.User != nil {
		return fmt.Errorf("statusserviceclient: %s carries credentials in the URL, which this client never uses and would leak wherever the endpoint is logged", name)
	}
	// This is a BASE url, and every call appends to it by string
	// concatenation: /token, /allocate, /status/{listID}/{idx}. A query or
	// a fragment swallows whatever follows it, so
	// "https://as.example/token?tenant=1" becomes
	// ".../token?tenant=1/token" - a request to the wrong path, with the
	// suffix buried in a parameter value, answered by something.
	//
	// Refused rather than stripped: an operator who wrote a query there
	// meant it to be sent, and quietly dropping it would be a different
	// wrong request. Nothing this client calls takes a base-url query.
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("statusserviceclient: %s %q carries a query string, but it is a base URL this client appends paths to, so the query would swallow them", name, raw)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("statusserviceclient: %s %q carries a fragment, but it is a base URL this client appends paths to, so the fragment would swallow them", name, raw)
	}
	// A dot segment in the BASE makes the configured endpoint and the
	// called one different: ".../v1/.." + "/allocate" is sent as
	// "/v1/../allocate", and whatever sits in front of the service
	// resolves it to "/allocate". The same rule a list ID is held to, for
	// the same reason - an endpoint that names one resource and resolves
	// to another.
	// u.Path, the PERCENT-DECODED form, which is the only one that catches
	// every spelling: "%2e%2e" arrives here as "..", and "a%2F.." has
	// already split into "a" and "..". The first version of this check
	// split EscapedPath instead, where "%2e%2e" is not "..", and the
	// escaped spelling walked straight past it.
	//
	// The decoded path is what ListIDFromURL has always checked. Checking
	// the same form here is what makes a configured endpoint and a derived
	// list ID held to one rule rather than two.
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("statusserviceclient: %s %q contains the dot segment %q, so the endpoint it names is not the one that would be called", name, raw, segment)
		}
	}
	return nil
}
