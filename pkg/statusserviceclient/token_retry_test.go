package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A 401 answering a CACHED token is the token being stale, not the service
// refusing. Classifying it permanent stops the retry loop dead, so the fresh
// token the 401 handler just arranged for is never actually tried - turning
// a routine expiry into a failed allocation.
func TestClassifyResourceStatus_UnauthorizedIsRetryable(t *testing.T) {
	err := classifyResourceStatus(http.StatusUnauthorized, []byte("token expired"))
	if err == nil {
		t.Fatal("a 401 is still an error")
	}
	if isPermanent(err) {
		t.Fatal("a cached-token 401 must be retryable, so the retry can fetch a fresh token")
	}
}

// Every other 4xx really is the service saying no, and retrying it would
// just hammer a service that has already refused.
func TestClassifyResourceStatus_OtherClientErrorsStayPermanent(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusGone, http.StatusBadRequest} {
		if err := classifyResourceStatus(code, []byte("no")); !isPermanent(err) {
			t.Fatalf("%d must stay permanent", code)
		}
	}
}

// The token endpoint is the other way round: a 4xx there is a real refusal
// of the client's credentials, so classifyStatus keeps its behaviour.
func TestClassifyStatus_TokenEndpointUnauthorizedStaysPermanent(t *testing.T) {
	if err := classifyStatus(http.StatusUnauthorized, []byte("bad assertion")); !isPermanent(err) {
		t.Fatal("a token-endpoint 401 must stay permanent: retrying rejected credentials is pointless")
	}
}

// maxElapsed used to be checked only BETWEEN attempts, while fn ran
// http.Client.Do on the caller's context - so a single stuck request could
// outlive the bound the config advertises (the transport's own timeout is
// 10s by default, against a 5s TakeFallbackTimeout).
func TestRetry_DeadlineCancelsTheInFlightCall(t *testing.T) {
	const bound = 80 * time.Millisecond

	start := time.Now()
	err := retry(context.Background(), retryConfig{
		initialBackoff: time.Millisecond,
		maxBackoff:     time.Millisecond,
		maxElapsed:     bound,
	}, func(ctx context.Context) error {
		// Stands in for a request that never answers: it returns only when
		// its context is cancelled.
		<-ctx.Done()
		return ctx.Err()
	})

	if err == nil {
		t.Fatal("want an error once the deadline passes")
	}
	if elapsed := time.Since(start); elapsed > bound*4 {
		t.Fatalf("retry took %v, well past its %v bound: the in-flight call was not cancelled", elapsed, bound)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("err = %v", err)
	}
}

// The bound must not leak into the caller's own context: cancelling the
// retry deadline cannot cancel whatever the caller does next.
func TestRetry_LeavesTheCallerContextAlone(t *testing.T) {
	ctx := context.Background()
	_ = retry(ctx, retryConfig{maxAttempts: 1, maxElapsed: time.Millisecond}, func(context.Context) error {
		return errors.New("nope")
	})
	if err := ctx.Err(); err != nil {
		t.Fatalf("caller context must be untouched, got %v", err)
	}
}

// getToken used to hold tokenMu across the whole retrying token exchange, so
// a caller arriving behind another fetch waited on a mutex - and a mutex
// wait cannot be cancelled. That made TakeFallbackTimeout unenforceable:
// the second caller's own deadline was ignored until the first one finished.
func TestGetToken_WaiterHonoursItsOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	var hits int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the first fetch open
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	defer close(release)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c, err := New(Config{
		IngestionURL: server.URL, ASURL: server.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// First caller: occupies the fetch and blocks on the server.
	go func() { _, _ = c.getToken(context.Background()) }()
	// Give it time to claim the single-flight slot.
	time.Sleep(50 * time.Millisecond)

	// Second caller: its own deadline must win.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.getToken(ctx); err == nil {
		t.Fatal("want the waiter's deadline to be honoured")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("waiter blocked %v: it was pinned behind the other fetch", elapsed)
	}
}

// assertListIDRejected requires ListIDFromURL to refuse url, naming the ID it
// handed back instead when it does not.
//
// Deriving a good-looking ID from an unusable URL is the bad outcome in every
// case below, which is why they share one assertion.
func assertListIDRejected(t *testing.T, name, url string) {
	t.Helper()

	t.Run(name, func(t *testing.T) {
		if id, err := ListIDFromURL(url); err == nil {
			t.Fatalf("%q must be rejected, got list ID %q", url, id)
		}
	})
}

// The list_url goes into a credential's status.status_list.uri as well as
// giving up the ID for PATCH, so anything a verifier could not resolve has
// to be refused. Deriving a good-looking ID from an unusable URL is the bad
// outcome: the client would PATCH the right entry while the credential
// carried a reference nobody can follow.
func TestListIDFromURL_RejectsUnusableURLs(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		// path.Base("/lists/") is "lists" - the collection, not a list.
		{"trailing slash", "https://status.example.org/lists/"},
		{"root only", "https://status.example.org/"},
		// Relative values yield an ID from something unresolvable.
		{"relative with path", "lists/abc"},
		{"bare segment", "abc"},
		{"scheme-relative", "//status.example.org/lists/abc"},
		{"path only", "/lists/abc"},
		// Schemes the verifier's StatusListChecker refuses outright, so a
		// credential referencing one could never have its status checked.
		{"ftp", "ftp://status.example.org/lists/abc"},
		{"file", "file:///etc/passwd"},
		{"data", "data:application/json,{}"},
	} {
		assertListIDRejected(t, tc.name, tc.url)
	}
}

// A dot segment makes the URL name one resource and resolve to another.
//
// As the last segment it becomes the list ID itself: url.PathEscape leaves
// ".." alone, Go sends the literal request-URI "/status/../5", and whatever
// sits in front of the ingestion service resolves that to "/5" - so the
// PATCH writes an entry on a list nobody asked for. Earlier in the path it
// yields a plausible ID while the credential carries a status_list.uri that
// a verifier resolves somewhere else entirely.
func TestListIDFromURL_RejectsDotSegments(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"escaped dot-dot as the ID", "https://status.example.org/lists/%2e%2e"},
		{"upper-case escape", "https://status.example.org/lists/%2E%2E"},
		{"literal dot-dot as the ID", "https://status.example.org/lists/.."},
		{"single dot as the ID", "https://status.example.org/lists/."},
		{"dot-dot earlier in the path", "https://status.example.org/lists/../admin/abc"},
		{"single dot earlier in the path", "https://status.example.org/lists/./abc"},
		{"escaped, earlier in the path", "https://status.example.org/lists/%2e%2e/admin/abc"},
	} {
		assertListIDRejected(t, tc.name, tc.url)
	}
}

// And a dot in the middle of a segment is an ordinary character - refusing
// those too would reject list IDs the service is free to hand out.
func TestListIDFromURL_AcceptsDotsWithinASegment(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://status.example.org/lists/a.b", "a.b"},
		{"https://status.example.org/lists/...", "..."},
		{"https://status.example.org/v1.0/lists/abc", "abc"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			id, err := ListIDFromURL(tc.url)
			if err != nil {
				t.Fatalf("%q must be accepted: %v", tc.url, err)
			}
			if id != tc.want {
				t.Fatalf("got %q, want %q", id, tc.want)
			}
		})
	}
}

// The shape the status service actually returns must still work.
func TestListIDFromURL_AcceptsAVerifierFacingURL(t *testing.T) {
	id, err := ListIDFromURL("https://status.example.org/lists/abc123")
	if err != nil {
		t.Fatalf("a well-formed list_url must be accepted: %v", err)
	}
	if id != "abc123" {
		t.Fatalf("got %q, want abc123", id)
	}
}

// A key on any other curve produces an assertion labelled ES256 that the
// status service rejects - and a rejection is retried, so the operator sees
// a slow loop of 4xx instead of the configuration error it is.
func TestNew_RejectsNonP256Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, err = New(Config{
		IngestionURL: "https://status.example.org",
		ASURL:        "https://as.example.org",
		IssuerID:     "https://issuer.example.org",
		Signer:       softwareSigner(key),
	}, nil)
	if err == nil {
		t.Fatal("a P-384 key must be rejected at construction")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("the error should name the required curve, got %v", err)
	}
}

// Every request this client makes goes to one of these two endpoints, so a
// scheme it cannot speak has to be refused at construction. Otherwise the
// issuer starts, serves, and fails on the first allocation with an obscure
// transport error.
func TestNew_RejectsEndpointsItCannotCall(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	base := func() Config {
		return Config{
			IngestionURL: "https://status.example.org",
			ASURL:        "https://as.example.org",
			IssuerID:     "https://issuer.example.org",
			Signer:       softwareSigner(key),
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"ingestion ftp", func(c *Config) { c.IngestionURL = "ftp://status.example.org" }, "IngestionURL"},
		{"as ftp", func(c *Config) { c.ASURL = "ftp://as.example.org" }, "ASURL"},
		{"ingestion file", func(c *Config) { c.IngestionURL = "file:///etc/passwd" }, "IngestionURL"},
		{"ingestion relative", func(c *Config) { c.IngestionURL = "status.example.org" }, "IngestionURL"},
		{"ingestion empty", func(c *Config) { c.IngestionURL = "" }, "IngestionURL"},
		{"as empty", func(c *Config) { c.ASURL = "" }, "ASURL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)

			_, err := New(cfg, nil)
			if err == nil {
				t.Fatal("want a refusal at construction")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error should name the field, got: %v", err)
			}
		})
	}
}

// And a well-formed pair still constructs.
func TestNew_AcceptsHTTPEndpoints(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c, err := New(Config{
		IngestionURL:   "http://status.example.org",
		ASURL:          "https://as.example.org",
		IssuerID:       "https://issuer.example.org",
		Signer:         softwareSigner(key),
		PoolSize:       0,
		RefillInterval: time.Hour,
	}, nil)
	if err != nil {
		t.Fatalf("plain http must be allowed (local deployments): %v", err)
	}
	c.Close()
}

// A base URL carrying a query or a fragment is refused at construction.
//
// Every call appends to these by string concatenation - /token, /allocate,
// /status/{listID}/{idx} - and a query or fragment swallows the suffix:
// "https://as.example/token?tenant=1" becomes ".../token?tenant=1/token",
// which is a request to the wrong path with the suffix buried in a
// parameter value. Nothing downstream can notice; the server answers
// whatever that resolves to.
func TestNewRejectsABaseURLThatWouldSwallowThePath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, bad string }{
		{"a query string", "https://as.example/token?tenant=1"},
		{"a bare question mark", "https://as.example?"},
		{"a fragment", "https://as.example#frag"},
		{"both", "https://as.example/v1?a=b#c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Once as the AS URL, once as the ingestion URL: both are
			// bases this client appends to, so both have to be held to it.
			for field, cfg := range map[string]Config{
				"ASURL": {
					IngestionURL: "https://status.example.org", ASURL: tc.bad,
					IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
				},
				"IngestionURL": {
					IngestionURL: tc.bad, ASURL: "https://as.example.org",
					IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
				},
			} {
				c, err := New(cfg, nil)
				if err == nil {
					c.Close()
					t.Fatalf("%s = %q must be refused", field, tc.bad)
				}
				// The MESSAGE, not just an error: New has several other
				// ways to fail, and any of them would satisfy a bare
				// err != nil while this guard was gone.
				if !strings.Contains(err.Error(), "query string") && !strings.Contains(err.Error(), "fragment") {
					t.Fatalf("%s = %q must be refused FOR its query or fragment, got: %v", field, tc.bad, err)
				}
			}
		})
	}
}

// And an ordinary base URL still builds, with or without a trailing slash.
func TestNewAcceptsAnOrdinaryBaseURL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, base := range []string{
		"https://status.example.org",
		"https://status.example.org/",
		"https://status.example.org/v1",
		"http://127.0.0.1:8080",
	} {
		c, err := New(Config{
			IngestionURL: base, ASURL: base,
			IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
			PoolSize: 0, RefillInterval: time.Hour,
		}, nil)
		if err != nil {
			t.Fatalf("%q must be accepted: %v", base, err)
		}
		c.Close()
	}
}

// A redirect away from a configured endpoint is refused, and nothing
// reaches the target.
//
// Measured rather than trusted to net/http. Go strips the Authorization
// header only when the redirect crosses to a different HOST, and even then
// it REPLAYS THE BODY on 307/308 - and the token request's body carries the
// RFC 7523 client assertion. A different PORT on the same host is not a
// different host to Go, so without a policy both the bearer token and the
// assertion travel to wherever the redirect names.
func TestAClientDoesNotFollowARedirect(t *testing.T) {
	var reached atomic.Int32
	var sawAuth, sawBody atomic.Value
	sawAuth.Store("")
	sawBody.Store("")

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		sawAuth.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		sawBody.Store(string(b))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	// 308: method and body are preserved across it, which is the case that
	// carries the client assertion.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	defer redirector.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		IngestionURL: redirector.URL, ASURL: redirector.URL,
		IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		PoolSize: 0, RefillInterval: time.Hour,
		RetryInitialBackoff: time.Millisecond, RetryMaxBackoff: 2 * time.Millisecond,
		TakeFallbackTimeout: 200 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.Take(context.Background()); err == nil {
		t.Fatal("a redirected endpoint must not yield an entry")
	}

	if n := reached.Load(); n != 0 {
		t.Fatalf("the redirect target was reached %d times; it must never be", n)
	}
	if got := sawAuth.Load().(string); got != "" {
		t.Fatalf("an access token reached the redirect target: %q", got)
	}
	if got := sawBody.Load().(string); strings.Contains(got, "client_assertion") {
		t.Fatalf("the client assertion reached the redirect target: %q", got)
	}
}

// A 429 is the service asking to be asked again, not refusing.
//
// Classified permanent, a rate-limited service fails the allocation
// outright - and an issuer on the default degraded mode then mints a
// credential with no status claim, unrevokable, because the service asked
// it to slow down. 408 is the same shape.
func TestRateLimitingIsRetriedRatherThanTreatedAsARefusal(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusRequestTimeout} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			if err := classifyStatus(code, []byte("slow down")); err == nil {
				t.Fatalf("%d is still an error", code)
			} else if isPermanent(err) {
				t.Fatalf("%d must be retryable, not a refusal", code)
			}
		})
	}

	// The control: an ordinary 4xx is still a refusal, or this test would
	// pass just as well with every 4xx made retryable.
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusGone} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			if err := classifyStatus(code, []byte("no")); !isPermanent(err) {
				t.Fatalf("%d must stay a refusal", code)
			}
		})
	}
}

// SetStatus is a public entry point, and its list ID has to survive being
// put in a path.
//
// url.PathEscape leaves a dot alone - it is unreserved - so ".." reaches
// the wire intact and the request-URI becomes "/status/../5". Go does not
// remove dot segments from a request URI; whatever sits in front of the
// ingestion service does, and the write lands on "/5". ListIDFromURL
// already refuses this when DERIVING an ID, but a caller reaches SetStatus
// with an ID out of its own storage.
func TestSetStatusRefusesAListIDThatWouldNotStayOneSegment(t *testing.T) {
	fake, c, entry := clientHoldingOneEntry(t)
	before := fake.statusCallCount.Load()

	for _, tc := range []struct{ name, listID string }{
		{"empty", ""},
		{"dot", "."},
		{"dot dot", ".."},
		{"a path", "lists/abc"},
		{"a traversal", "../admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.SetStatus(context.Background(), tc.listID, entry.Index, StatusInvalid)
			if err == nil {
				t.Fatalf("list ID %q must be refused", tc.listID)
			}
			if !isPermanent(err) {
				t.Fatalf("list ID %q is not going to become valid; refusal must be permanent, got %v", tc.listID, err)
			}
		})
	}

	if got := fake.statusCallCount.Load(); got != before {
		t.Fatalf("a refused list ID must never reach the network; %d request(s) went out", got-before)
	}
}

// And an ordinary list ID still works, or the test above would pass with
// SetStatus refusing everything.
func TestSetStatusAcceptsTheListIDItWasHandedByAllocate(t *testing.T) {
	_, c, entry := clientHoldingOneEntry(t)

	if err := c.SetStatus(context.Background(), entry.ListID, entry.Index, StatusInvalid); err != nil {
		t.Fatalf("the ID allocate handed back must be usable: %v", err)
	}
}

// A list ID is derived from the ESCAPED path, and must be one this client
// can reproduce.
//
// url.URL.Path is already percent-decoded, so ".../lists/a%2Fb" reads as
// "/lists/a/b" and path.Base returns "b" - the tail of a list ID rather
// than the list ID. The credential would carry a status_list.uri a verifier
// resolves to the list "a/b" while every PATCH went to a list called "b":
// status updates landing on the wrong list, silently, for the life of the
// credential.
func TestListIDFromURL_RefusesASegmentItCannotReproduce(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"an escaped slash", "https://status.example.org/lists/a%2Fb"},
		{"a redundantly escaped letter", "https://status.example.org/lists/%41%42"},
		{"an embedded NUL", "https://status.example.org/lists/abc%00"},
	} {
		assertListIDRejected(t, tc.name, tc.url)
	}
}

// The control: an ordinary ID still comes back, including one carrying the
// characters a list ID is allowed to carry.
func TestListIDFromURL_StillAcceptsAnOrdinaryID(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://status.example.org/lists/abc123", "abc123"},
		{"https://status.example.org/lists/a-b_c.d", "a-b_c.d"},
		{"https://status.example.org:8443/lists/abc", "abc"},
	} {
		got, err := ListIDFromURL(tc.url)
		if err != nil {
			t.Fatalf("%q must be accepted: %v", tc.url, err)
		}
		if got != tc.want {
			t.Fatalf("%q -> %q, want %q", tc.url, got, tc.want)
		}
	}
}

// A dot segment in a configured BASE url makes the endpoint named and the
// endpoint called two different things: ".../v1/.." + "/allocate" goes out
// as "/v1/../allocate", which anything in front of the service resolves to
// "/allocate".
func TestNewRejectsABaseURLWithADotSegment(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"https://status.example.org/v1/..",
		"https://status.example.org/..",
		"https://status.example.org/./v1",
		"https://status.example.org/a/../b",
	} {
		c, err := New(Config{
			IngestionURL: bad, ASURL: "https://as.example.org",
			IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		}, nil)
		if err == nil {
			c.Close()
			t.Fatalf("%q must be refused", bad)
		}
		if !strings.Contains(err.Error(), "dot segment") {
			t.Fatalf("%q must be refused FOR its dot segment, got: %v", bad, err)
		}
	}
}

// An ESCAPED dot segment is a dot segment.
//
// u.Path is percent-decoded and u.EscapedPath is not, so "/v1/.." appears
// only in the first and "/v1/%2e%2e" only in the second. Checking one form
// is how the escaped spelling walked past this check when it was added;
// ListIDFromURL has always checked the decoded path, and the two now agree.
func TestNewRejectsAnEscapedDotSegmentInTheBaseURL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Each spelling is caught by a different half of the check, which is
	// why both halves exist:
	//
	//   %2e%2e  - the escaped segment unescapes to "..", so unescaping
	//             each segment is what catches it.
	//   %2F..   - the escaped path splits as one segment "a%2F..", which
	//             unescapes to "a/.." and is not a dot segment; only the
	//             DECODED path splits it into "a" and "..".
	for _, bad := range []string{
		"https://status.example.org/v1/%2e%2e",
		"https://status.example.org/v1/%2E%2E",
		"https://status.example.org/v1/%2e",
		"https://status.example.org/%2e%2e/admin",
		"https://status.example.org/a%2F..",
		"https://status.example.org/a%2f%2e%2e",
	} {
		c, err := New(Config{
			IngestionURL: bad, ASURL: "https://as.example.org",
			IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		}, nil)
		if err == nil {
			c.Close()
			t.Fatalf("%q must be refused", bad)
		}
		if !strings.Contains(err.Error(), "dot segment") {
			t.Fatalf("%q must be refused FOR its dot segment, got: %v", bad, err)
		}
	}
}

// An AllocateExpiry at or below the expiry skew is refused at startup.
//
// The service answers with now+AllocateExpiry and expired() discards
// anything inside entryExpirySkew of now, so every entry would be born
// unusable - and each refill cycle would allocate one, mark it invalid to
// release it, and give up until the next cycle. One remote index burned per
// cycle for the life of the process, the pool never filling, every issuance
// in degraded mode. The cause is a constant, so it is decidable once here.
func TestNewRejectsAnAllocateExpiryInsideTheSkew(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := func(exp time.Duration) Config {
		return Config{
			IngestionURL: "https://status.example.org", ASURL: "https://as.example.org",
			IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
			PoolSize: 0, RefillInterval: time.Hour, AllocateExpiry: exp,
		}
	}

	for _, bad := range []time.Duration{time.Second, 30 * time.Second, entryExpirySkew} {
		c, err := New(base(bad), nil)
		if err == nil {
			c.Close()
			t.Fatalf("AllocateExpiry %s must be refused", bad)
		}
		if !strings.Contains(err.Error(), "expiry skew") {
			t.Fatalf("AllocateExpiry %s must be refused FOR the skew, got: %v", bad, err)
		}
	}

	// Zero means "take the service's own maximum", and a value above the
	// skew is the ordinary case: neither is refused.
	for _, ok := range []time.Duration{0, entryExpirySkew + time.Second, 24 * time.Hour} {
		c, err := New(base(ok), nil)
		if err != nil {
			t.Fatalf("AllocateExpiry %s must be accepted: %v", ok, err)
		}
		c.Close()
	}
}

// Credentials in a base URL are refused: this client authenticates with a
// client assertion and a bearer token, so userinfo is inert here, would be
// sent as basic auth alongside the Authorization header, and would appear
// wherever the endpoint is logged.
func TestNewRejectsCredentialsInABaseURL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"https://user:pw@status.example.org",
		"https://user@status.example.org",
	} {
		c, err := New(Config{
			IngestionURL: bad, ASURL: "https://as.example.org",
			IssuerID: "https://issuer.example.org", Signer: softwareSigner(key),
		}, nil)
		if err == nil {
			c.Close()
			t.Fatalf("%q must be refused", bad)
		}
		// The message must not echo the URL, or refusing it would be the
		// thing that copies the password into the log.
		if strings.Contains(err.Error(), "pw") {
			t.Fatalf("the refusal must not print the credentials: %v", err)
		}
	}
}

// A list URL carrying credentials is refused, because that URL is
// PUBLISHED: it becomes the credential's status.status_list.uri, which
// every holder keeps and every verifier fetches.
func TestListIDFromURL_RefusesCredentialsInAPublishedURL(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"user and password", "https://user:pw@status.example.org/lists/abc"},
		{"user only", "https://token@status.example.org/lists/abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ListIDFromURL(tc.url)
			if err == nil {
				t.Fatalf("%q must be rejected, got list ID %q", tc.url, id)
			}
			// Refusing it must not be the thing that logs the secret.
			if strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "token@") {
				t.Fatalf("the refusal must not echo the credentials: %v", err)
			}
		})
	}
}

// No diagnostic prints a credential, whatever the URL is wrong about.
//
// The userinfo check cannot be the only guard: the scheme, host, query,
// fragment and dot-segment checks each refuse a URL too, and each ran
// before or instead of it. A URL that is wrong in two ways at once -
// credentials AND a bad scheme - was refused for the scheme, printing the
// password while doing it.
func TestNoURLDiagnosticEchoesACredential(t *testing.T) {
	const secret = "sup3rsecret"

	for _, tc := range []struct{ name, url string }{
		{"bad scheme", "ftp://user:" + secret + "@status.example.org"},
		{"no host", "https://user:" + secret + "@"},
		{"query", "https://user:" + secret + "@status.example.org?a=b"},
		{"fragment", "https://user:" + secret + "@status.example.org#f"},
		{"dot segment", "https://user:" + secret + "@status.example.org/v1/.."},
		{"credentials alone", "https://user:" + secret + "@status.example.org"},
		{"unparseable", "https://user:" + secret + "@status.example.org/%zz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireHTTPEndpoint("IngestionURL", tc.url)
			if err == nil {
				t.Fatalf("%q must be refused", tc.url)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refusal printed the credential: %v", err)
			}
		})
	}

	// The same for a list URL, whose own checks run before its userinfo
	// check for the same reason.
	for _, bad := range []string{
		"lists/abc",
		"https://user:" + secret + "@status.example.org/lists/abc#f",
		"https://user:" + secret + "@status.example.org/lists/abc",
	} {
		if _, err := ListIDFromURL(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		} else if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal printed the credential: %v", err)
		}
	}
}

// A token in the USERNAME position is redacted too, which url.URL.Redacted
// does not do.
func TestRedactURLBlanksTheWholeUserinfo(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://sometoken@status.example.org/x", "https://xxxxx@status.example.org/x"},
		{"https://user:pw@status.example.org/x", "https://xxxxx@status.example.org/x"},
		{"https://status.example.org/x", "https://status.example.org/x"},
		// Never printed: the reason it would not parse may be the secret.
		{"https://user:pw@status.example.org/a%zz", "<unparseable url>"},
	} {
		if got := redactURL(tc.in); got != tc.want {
			t.Fatalf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
