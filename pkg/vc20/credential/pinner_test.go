package credential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unreachable is a URL that never resolves. httptest is no use here: the
// loader refuses to dial loopback, and a reused port can leave a previous
// test's document in the process-wide cache (#873).
const unreachable = "https://ctx.invalid/pinner-test.jsonld"

// testClock drives a Pinner without any real time passing, and records what
// it was asked to wait for - the retry schedule is a behaviour of its own,
// not an implementation detail, and asserting on recorded waits is the only
// way to check it without making the suite take that long.
type testClock struct {
	now    time.Time
	slept  []time.Duration
	onWake func()
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) Sleep(d time.Duration) {
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	if c.onWake != nil {
		c.onWake()
	}
}

// advance moves the clock on, so work scheduled for later falls due.
func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestPinner(t *testing.T, loader *CachingDocumentLoader, clock *testClock, opts PinnerOptions) *Pinner {
	t.Helper()
	opts.now = clock.Now
	opts.sleep = clock.Sleep
	p := NewPinner(loader, opts)
	t.Cleanup(p.Stop)
	return p
}

func scopeGroup(urls ...string) PinGroup {
	return PinGroup{
		Name:        "common.credential_metadata.diploma",
		Field:       "credential_contexts",
		URLs:        urls,
		Consequence: "so presentations of this credential type cannot be verified",
	}
}

// Under "required" the boot is refused, and the message has to carry every
// part an operator needs: which setting, which URL, and what this service
// loses by it.
func TestPinnerRequiredRefusesTheBoot(t *testing.T) {
	loader := NewCachingDocumentLoader()
	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyRequired})

	err := p.Pin(context.Background(), []PinGroup{scopeGroup(unreachable)})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "common.credential_metadata.diploma")
	assert.Contains(t, err.Error(), "credential_contexts")
	assert.Contains(t, err.Error(), unreachable)
	assert.Contains(t, err.Error(), "so presentations of this credential type cannot be verified")
}

// Under "best_effort" the service starts - and is NOT ready. Reporting
// ready would put a verifier that cannot canonicalize this credential type
// into a load balancer as though it could, which is the only thing that
// makes starting at all defensible.
func TestPinnerBestEffortStartsNotReadyThenRecovers(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyBestEffort})

	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(unreachable)}),
		"best_effort must not fail the boot")

	err := p.HealthProbe(context.Background())
	require.Error(t, err, "a context that has not loaded must fail readiness")
	assert.Contains(t, err.Error(), unreachable, "readiness has to name what it is waiting for")
	assert.Equal(t, []string{unreachable}, p.Pending())

	// The context becomes available, and the background pass picks it up.
	seedWithTTL(t, loader, unreachable, `{"@context":{"Diploma":"https://example.org/Diploma"}}`)
	clock.advance(time.Hour)
	p.tick(context.Background())

	assert.NoError(t, p.HealthProbe(context.Background()))
	assert.Empty(t, p.Pending())
}

// "lazy" fetches nothing at startup. Proven by the cache staying empty: a
// pin would have put the document there, with no expiry.
func TestPinnerLazyPinsNothing(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/lazy.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"Lazy":"https://example.org/Lazy"}}`)

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyLazy})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(url)}))

	assert.False(t, pinned(t, loader, url), "lazy must leave the document on the ordinary TTL")
	assert.NoError(t, p.HealthProbe(context.Background()),
		"lazy gates readiness on nothing, which is what choosing it asks for")
	assert.Empty(t, p.Pending())
}

// The boot retries before the policy decides, with a growing wait. A
// deployment whose context host is a second behind the service should not
// need best_effort to survive it.
func TestPinnerRetriesDuringBoot(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	p := newTestPinner(t, loader, clock, PinnerOptions{
		Policy: PolicyRequired,
		Retry: RetryPolicy{
			InitialInterval: time.Second,
			MaxInterval:     time.Minute,
			Multiplier:      2,
			BootAttempts:    3,
		},
	})

	err := p.Pin(context.Background(), []PinGroup{scopeGroup(unreachable)})

	require.Error(t, err)
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second}, clock.slept,
		"two waits for three attempts, growing by the multiplier")
}

// And a context that appears between attempts is picked up by the boot
// itself, rather than leaving the service to start degraded.
func TestPinnerBootSucceedsOnALaterAttempt(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	const url = "https://ctx.example.org/late.jsonld"

	// The context arrives while the first backoff is being waited out.
	clock.onWake = func() {
		seedWithTTL(t, loader, url, `{"@context":{"Late":"https://example.org/Late"}}`)
		clock.onWake = nil
	}

	p := newTestPinner(t, loader, clock, PinnerOptions{
		Policy: PolicyRequired,
		Retry:  RetryPolicy{InitialInterval: time.Second, MaxInterval: time.Minute, Multiplier: 2, BootAttempts: 3},
	})

	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(url)}))
	assert.Len(t, clock.slept, 1, "it must stop retrying as soon as it succeeds")
	assert.True(t, pinned(t, loader, url))
}

// The deferred check needs the WHOLE group: expanding a scope's types needs
// every one of that scope's contexts, so running it when the first of two
// arrives would report terms undefined that the second defines.
func TestPinnerVerifyWaitsForTheWholeGroup(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	const present = "https://ctx.example.org/present.jsonld"
	seedWithTTL(t, loader, present, `{"@context":{"A":"https://example.org/A"}}`)

	verified := 0
	group := scopeGroup(present, unreachable)
	group.Verify = func() error { verified++; return nil }

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))
	require.Equal(t, 0, verified, "one context of two is not enough to expand against")

	seedWithTTL(t, loader, unreachable, `{"@context":{"B":"https://example.org/B"}}`)
	clock.advance(time.Hour)
	p.tick(context.Background())

	assert.Equal(t, 1, verified)
	assert.NoError(t, p.HealthProbe(context.Background()))
}

// A deferred check that fails cannot stop a process that has already
// started, so readiness is where it has to surface - otherwise a verifier
// whose configured types no context defines reports healthy for the life of
// the process.
func TestPinnerVerifyFailureFailsReadiness(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/verify-fails.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"A":"https://example.org/A"}}`)

	group := scopeGroup(url)
	group.Verify = func() error { return errors.New("credential_contexts defines none of DiplomaCredential") }

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))

	err := p.HealthProbe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "defines none of")
}

// Under "required" the same failure is fatal, which is what required means.
func TestPinnerVerifyFailureUnderRequiredRefusesTheBoot(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/verify-fails-required.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"A":"https://example.org/A"}}`)

	group := scopeGroup(url)
	group.Verify = func() error { return errors.New("credential_contexts defines none of DiplomaCredential") }

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyRequired})

	err := p.Pin(context.Background(), []PinGroup{group})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "defines none of")
}

// writeContext writes a context document and returns its path.
func writeContext(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// Refreshing re-reads a pinned context, and a refresh that FAILS keeps the
// copy already pinned. A context host that goes away must not take a
// running service with it - that is the whole reason refreshing is safe to
// turn on.
func TestPinnerRefreshSwapsOnSuccessAndKeepsTheLastGoodCopy(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const url = "https://ctx.example.org/refreshed.jsonld"
	path := writeContext(t, dir, "ctx.jsonld", `{"@context":{"Version":"https://example.org/v1"}}`)
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	p := newTestPinner(t, loader, clock, PinnerOptions{
		Policy:          PolicyRequired,
		RefreshInterval: time.Hour,
	})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(url)}))
	require.Equal(t, "https://example.org/v1", termIRI(t, loader, url, "Version"))

	// The document changes at its source and the refresh picks it up.
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"Version":"https://example.org/v2"}}`), 0o600))
	clock.advance(2 * time.Hour)
	p.tick(context.Background())
	assert.Equal(t, "https://example.org/v2", termIRI(t, loader, url, "Version"),
		"a refresh must actually re-read, not serve the pinned copy back to itself")

	// The source then becomes unreadable. The last copy that loaded stays,
	// and the service stays ready.
	require.NoError(t, os.Remove(path))
	clock.advance(2 * time.Hour)
	p.tick(context.Background())

	assert.Equal(t, "https://example.org/v2", termIRI(t, loader, url, "Version"),
		"a failed refresh must leave the last good copy in place")
	assert.NoError(t, p.HealthProbe(context.Background()),
		"the service is still serving what it validated, so it is still ready")
}

// termIRI reads one term's IRI out of a cached context document.
func termIRI(t *testing.T, l *CachingDocumentLoader, url, term string) string {
	t.Helper()
	item := l.cache.Get(url)
	require.NotNil(t, item, "%s is not cached", url)
	document, ok := item.Value().Document.(map[string]any)
	require.True(t, ok, "%s is not a JSON object", url)
	ctx, ok := document["@context"].(map[string]any)
	require.True(t, ok, "%s has no @context object", url)
	iri, _ := ctx[term].(string)
	return iri
}

// The backoff grows and then stops growing. Computed in float on purpose:
// multiplying a duration enough times overflows int64 into a NEGATIVE wait,
// which turns a backoff into a spin against the very host that is already
// failing.
func TestRetryBackoffIsCappedAndNeverNegative(t *testing.T) {
	retry := RetryPolicy{InitialInterval: time.Second, MaxInterval: time.Minute, Multiplier: 2}

	assert.Equal(t, time.Second, retry.backoff(1))
	assert.Equal(t, 2*time.Second, retry.backoff(2))
	assert.Equal(t, 4*time.Second, retry.backoff(3))
	assert.Equal(t, time.Minute, retry.backoff(10), "capped at max_interval")

	for _, failures := range []int{64, 1000, 1 << 20} {
		wait := retry.backoff(failures)
		assert.Equal(t, time.Minute, wait, "a long outage must stay at the cap, not overflow")
		assert.Positive(t, wait)
	}
}

// A zero-value RetryPolicy is what a deployment that configures nothing
// gets in code paths that build one by hand; it must still make sense.
func TestRetryBackoffDefaultsAreUsable(t *testing.T) {
	var retry RetryPolicy
	assert.Equal(t, 1, retry.bootAttempts(), "one attempt is the behaviour that predates this stanza")
	assert.Positive(t, retry.backoff(1))
	assert.Equal(t, 5*time.Minute, retry.backoff(1000))
}

// Nothing to retry and nothing to refresh means no background goroutine at
// all, rather than one that wakes every few minutes to find no work.
func TestPinnerStartsNoLoopWithNothingToDo(t *testing.T) {
	loader := NewCachingDocumentLoader()
	const url = "https://ctx.example.org/quiet.jsonld"
	seedWithTTL(t, loader, url, `{"@context":{"A":"https://example.org/A"}}`)

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyRequired})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(url)}))

	assert.False(t, p.hasWork())
}
