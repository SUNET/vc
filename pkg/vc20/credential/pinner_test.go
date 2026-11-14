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

	// Configured to come from a file that is not there yet, so "the
	// context is unavailable" is a real load failure and not a cache miss.
	path := filepath.Join(t.TempDir(), "diploma.jsonld")
	loader.SetContextSources(map[string]ContextSource{unreachable: {File: path}})

	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(unreachable)}),
		"best_effort must not fail the boot")

	err := p.HealthProbe(context.Background())
	require.Error(t, err, "a context that has not loaded must fail readiness")
	assert.Contains(t, err.Error(), unreachable, "readiness has to name what it is waiting for")
	assert.Equal(t, []string{unreachable}, p.Pending())

	// The context becomes available, and the background pass picks it up.
	require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"Diploma":"https://example.org/Diploma"}}`), 0o600))
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
	const url = "https://ctx.invalid/late.jsonld"
	path := filepath.Join(t.TempDir(), "late.jsonld")
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	// The context arrives while the first backoff is being waited out.
	clock.onWake = func() {
		require.NoError(t, os.WriteFile(path, []byte(`{"@context":{"Late":"https://example.org/Late"}}`), 0o600))
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
	dir := t.TempDir()
	const present = "https://ctx.invalid/present.jsonld"
	presentPath := writeContext(t, dir, "present.jsonld", `{"@context":{"A":"https://example.org/A"}}`)
	latePath := filepath.Join(dir, "late.jsonld")
	loader.SetContextSources(map[string]ContextSource{
		present:     {File: presentPath},
		unreachable: {File: latePath},
	})

	verified := 0
	group := scopeGroup(present, unreachable)
	group.Verify = func() error { verified++; return nil }

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))
	require.Equal(t, 0, verified, "one context of two is not enough to expand against")

	require.NoError(t, os.WriteFile(latePath, []byte(`{"@context":{"B":"https://example.org/B"}}`), 0o600))
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

// A refresh that replaces SOME of a group's documents and then fails on
// another leaves the cache holding fresh documents beside stale ones - a
// combination nothing has expanded the configured types against. Keeping
// the previous verdict would report a service healthy on the strength of a
// check run against a set of documents that is no longer in use.
func TestPinnerPartialRefreshRechecksTheTypes(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const first = "https://ctx.invalid/partial-first.jsonld"
	const second = "https://ctx.invalid/partial-second.jsonld"
	firstPath := writeContext(t, dir, "first.jsonld", `{"@context":{"A":"https://example.org/A"}}`)
	secondPath := writeContext(t, dir, "second.jsonld", `{"@context":{"B":"https://example.org/B"}}`)
	loader.SetContextSources(map[string]ContextSource{
		first:  {File: firstPath},
		second: {File: secondPath},
	})

	verified := 0
	group := scopeGroup(first, second)
	group.Verify = func() error { verified++; return nil }

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyRequired, RefreshInterval: time.Hour})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))
	require.Equal(t, 1, verified)

	// The first document changes and the second becomes unreadable, so the
	// refresh half succeeds.
	require.NoError(t, os.WriteFile(firstPath, []byte(`{"@context":{"A":"https://example.org/A2"}}`), 0o600))
	require.NoError(t, os.Remove(secondPath))
	clock.advance(2 * time.Hour)
	p.tick(context.Background())

	assert.Equal(t, "https://example.org/A2", termIRI(t, loader, first, "A"),
		"precondition: the refresh did replace one of the two")
	assert.Equal(t, 2, verified,
		"a mixed set of documents has to be checked, not inherit the old verdict")
}

// A refresh that replaces nothing does not re-run the check: there is no
// new combination to check, and expanding is not free.
func TestPinnerFullyFailedRefreshDoesNotRecheck(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const url = "https://ctx.invalid/no-recheck.jsonld"
	path := writeContext(t, dir, "ctx.jsonld", `{"@context":{"A":"https://example.org/A"}}`)
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	verified := 0
	group := scopeGroup(url)
	group.Verify = func() error { verified++; return nil }

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyRequired, RefreshInterval: time.Hour})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))
	require.Equal(t, 1, verified)

	require.NoError(t, os.Remove(path))
	clock.advance(2 * time.Hour)
	p.tick(context.Background())

	assert.Equal(t, 1, verified, "nothing was replaced, so the previous verdict still describes what is cached")
}

// A group whose contexts are pinned but whose deferred check has not run
// yet is NOT ready. attempt clears pending and releases the lock before
// running Verify, and a probe landing in that window must not report a
// service healthy a moment before the check it depends on fails.
func TestPinnerIsNotReadyUntilTheDeferredCheckHasPassed(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	const url = "https://ctx.invalid/not-checked-yet.jsonld"
	path := writeContext(t, dir, "ctx.jsonld", `{"@context":{"A":"https://example.org/A"}}`)
	loader.SetContextSources(map[string]ContextSource{url: {File: path}})

	probedDuringVerify := make(chan error, 1)
	group := scopeGroup(url)

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyBestEffort})
	// Probe from INSIDE the check, which is exactly the window: pending is
	// already empty and verifyErr is still nil.
	group.Verify = func() error {
		probedDuringVerify <- p.HealthProbe(context.Background())
		return nil
	}

	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))

	err := <-probedDuringVerify
	require.Error(t, err, "readiness must fail closed while the check is still outstanding")
	assert.Contains(t, err.Error(), "not checked against their contexts yet")

	assert.NoError(t, p.HealthProbe(context.Background()), "and pass once it has passed")
}

// A root whose reference fails is left cached with no expiry, because
// pinContext caches each document before walking its references. A retry
// that read the cache would reuse that stale root forever and never see the
// corrected document it is retrying for.
func TestPinnerRetryRereadsTheSourceRatherThanTheCache(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const root = "https://ctx.invalid/stale-root.jsonld"
	const leaf = "https://ctx.invalid/stale-leaf.jsonld"
	rootPath := writeContext(t, dir, "root.jsonld", `{"@context":["`+leaf+`",{"Root":"https://example.org/Root"}]}`)
	leafPath := filepath.Join(dir, "leaf.jsonld")
	loader.SetContextSources(map[string]ContextSource{
		root: {File: rootPath},
		leaf: {File: leafPath},
	})

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(root)}))
	require.Error(t, p.HealthProbe(context.Background()), "precondition: the missing leaf leaves the group pending")

	// The operator corrects the ROOT so it no longer references the leaf.
	// A retry serving the root from cache would never notice.
	require.NoError(t, os.WriteFile(rootPath, []byte(`{"@context":{"Root":"https://example.org/Root"}}`), 0o600))
	clock.advance(time.Hour)
	p.tick(context.Background())

	assert.NoError(t, p.HealthProbe(context.Background()),
		"the retry has to re-read the root, not reuse the copy pinned beside a failed reference")
	assert.Empty(t, p.Pending())
}

// The same staleness applies to the BOOT retries, which is where it
// matters most: the first attempt caches the root beside its failed
// reference, and an operator fixing the document while the boot is still
// retrying must be seen. A retry reading the cache would fail the boot
// against a document that has already been corrected.
func TestPinnerBootRetryRereadsTheSource(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const root = "https://ctx.invalid/boot-stale-root.jsonld"
	const leaf = "https://ctx.invalid/boot-stale-leaf.jsonld"
	rootPath := writeContext(t, dir, "root.jsonld", `{"@context":["`+leaf+`",{"Root":"https://example.org/Root"}]}`)
	loader.SetContextSources(map[string]ContextSource{
		root: {File: rootPath},
		leaf: {File: filepath.Join(dir, "never-written.jsonld")},
	})

	// The root is corrected during the first backoff, by which time the
	// first attempt has already cached the original with no expiry.
	clock.onWake = func() {
		require.NoError(t, os.WriteFile(rootPath, []byte(`{"@context":{"Root":"https://example.org/Root"}}`), 0o600))
		clock.onWake = nil
	}

	p := newTestPinner(t, loader, clock, PinnerOptions{
		Policy: PolicyRequired,
		Retry:  RetryPolicy{InitialInterval: time.Second, MaxInterval: time.Minute, Multiplier: 2, BootAttempts: 2},
	})

	assert.NoError(t, p.Pin(context.Background(), []PinGroup{scopeGroup(root)}),
		"the second attempt has to re-read the root, not the copy the first attempt cached")
}

// Closures overlap. One scope's root can reference a context another scope
// also uses, and a refresh replaces every document it reaches - so a group
// that was verified against the previous copy of a shared context would
// otherwise keep that verdict, indefinitely when refreshing is off.
func TestPinnerRecheckesOtherGroupsWhenASharedContextChanges(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const shared = "https://ctx.invalid/shared.jsonld"
	const bRoot = "https://ctx.invalid/b-root.jsonld"
	sharedPath := writeContext(t, dir, "shared.jsonld", `{"@context":{"S":"https://example.org/S"}}`)
	bRootPath := filepath.Join(dir, "b-root.jsonld")
	loader.SetContextSources(map[string]ContextSource{
		shared: {File: sharedPath},
		bRoot:  {File: bRootPath},
	})

	aVerified := 0
	groupA := scopeGroup(shared)
	groupA.Name = "common.credential_metadata.a"
	groupA.Verify = func() error { aVerified++; return nil }

	groupB := scopeGroup(bRoot)
	groupB.Name = "common.credential_metadata.b"
	groupB.Verify = func() error { return nil }

	// Refreshing OFF, which is the case where a stale verdict would never
	// be corrected by anything else.
	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{groupA, groupB}))
	require.Equal(t, 1, aVerified, "precondition: A verified against the shared context")

	// B's root turns up, and references the context A was verified
	// against - which B's retry re-fetches, replacing A's copy.
	require.NoError(t, os.WriteFile(bRootPath,
		[]byte(`{"@context":["`+shared+`",{"B":"https://example.org/B"}]}`), 0o600))
	require.NoError(t, os.WriteFile(sharedPath, []byte(`{"@context":{"S":"https://example.org/S2"}}`), 0o600))
	clock.advance(time.Hour)
	p.tick(context.Background())

	assert.Equal(t, "https://example.org/S2", termIRI(t, loader, shared, "S"),
		"precondition: B's retry did replace the shared document")
	assert.Equal(t, 2, aVerified,
		"A has to be re-checked against the context that was swapped under it")
}

// pinContext caches each document BEFORE walking its references, so a
// refresh that fails on a reference has already replaced the documents
// above it. Treating that as "nothing changed" leaves the group's verdict
// describing documents the cache no longer holds.
func TestPinnerFailedRefreshThatStillReplacedDocumentsRechecks(t *testing.T) {
	loader := NewCachingDocumentLoader()
	clock := newTestClock()
	dir := t.TempDir()
	const root = "https://ctx.invalid/writes-then-fails.jsonld"
	const leaf = "https://ctx.invalid/writes-then-fails-leaf.jsonld"
	rootPath := writeContext(t, dir, "root.jsonld", `{"@context":{"Root":"https://example.org/Root"}}`)
	loader.SetContextSources(map[string]ContextSource{
		root: {File: rootPath},
		leaf: {File: filepath.Join(dir, "never-written.jsonld")},
	})

	verified := 0
	group := scopeGroup(root)
	group.Verify = func() error { verified++; return nil }

	p := newTestPinner(t, loader, clock, PinnerOptions{Policy: PolicyRequired, RefreshInterval: time.Hour})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{group}))
	require.Equal(t, 1, verified)

	// The root now references a context that cannot be loaded. The
	// refresh replaces the root and then fails on the reference.
	require.NoError(t, os.WriteFile(rootPath,
		[]byte(`{"@context":["`+leaf+`",{"Root":"https://example.org/Root"}]}`), 0o600))
	clock.advance(2 * time.Hour)
	p.tick(context.Background())

	assert.Equal(t, 2, verified,
		"the root was replaced before the reference failed, so the group has to be re-checked")
}

// Under "required" the aggregate decides. A later group's pin can replace
// a context an EARLIER group was already verified against, and the recheck
// records that where only readiness sees it - so a boot that consulted
// nothing but its own loop would start a service whose first scope no
// longer checks out.
func TestPinnerRequiredRefusesWhenALaterGroupBreaksAnEarlierOne(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	const shared = "https://ctx.invalid/required-shared.jsonld"
	const later = "https://ctx.invalid/required-later.jsonld"
	sharedPath := writeContext(t, dir, "shared.jsonld", `{"@context":{"S":"https://example.org/S"}}`)
	// The later group's root replaces the shared document as it is pinned.
	laterPath := writeContext(t, dir, "later.jsonld", `{"@context":["`+shared+`",{"L":"https://example.org/L"}]}`)
	loader.SetContextSources(map[string]ContextSource{
		shared: {File: sharedPath},
		later:  {File: laterPath},
	})

	firstChecks := 0
	first := scopeGroup(shared)
	first.Name = "common.credential_metadata.first"
	first.Verify = func() error {
		firstChecks++
		if firstChecks == 1 {
			return nil
		}
		return errors.New("credential_contexts defines none of DiplomaCredential")
	}

	second := scopeGroup(later)
	second.Name = "common.credential_metadata.second"
	second.Verify = func() error { return nil }

	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyRequired})

	err := p.Pin(context.Background(), []PinGroup{first, second})

	require.Error(t, err, "required must not start a service whose first scope stopped checking out")
	assert.Contains(t, err.Error(), "defines none of")
	assert.Equal(t, 2, firstChecks, "the first group has to be re-checked after the second pinned")
}

// An ordinary pin writes just as a refresh does - only the cache LOOKUP
// differs - so the write flag has to come back from both. The background
// retry always refreshes, so the non-refresh flag matters on the STARTUP
// pass: a group pinned later in that pass can settle a context an earlier
// group needed, and without the flag the earlier group keeps the verdict
// it reached while that context was missing. Under best_effort with
// refreshing off, nothing would ever revisit it.
func TestPinnerFirstTimePinRechecksSharingGroups(t *testing.T) {
	loader := NewCachingDocumentLoader()
	dir := t.TempDir()
	const earlyURL = "https://ctx.invalid/early.jsonld"
	const lateURL = "https://ctx.invalid/late-in-pass.jsonld"
	loader.SetContextSources(map[string]ContextSource{
		earlyURL: {File: writeContext(t, dir, "early.jsonld", `{"@context":{"E":"https://example.org/E"}}`)},
		lateURL:  {File: writeContext(t, dir, "late.jsonld", `{"@context":{"L":"https://example.org/L"}}`)},
	})

	// The early group expands against something the LATER group pins, so
	// its first check fails and its second succeeds.
	checks := 0
	early := scopeGroup(earlyURL)
	early.Name = "common.credential_metadata.early"
	early.Verify = func() error {
		checks++
		if checks == 1 {
			return errors.New("credential_contexts defines none of DiplomaCredential")
		}
		return nil
	}

	late := scopeGroup(lateURL)
	late.Name = "common.jsonld_contexts.sources"
	late.Verify = func() error { return nil }

	// Refreshing OFF, so the startup pass is the only thing that runs.
	p := newTestPinner(t, loader, newTestClock(), PinnerOptions{Policy: PolicyBestEffort})
	require.NoError(t, p.Pin(context.Background(), []PinGroup{early, late}))

	assert.Equal(t, 2, checks, "pinning the later group has to recheck the earlier one")
	assert.NoError(t, p.HealthProbe(context.Background()),
		"the earlier group must not keep the verdict it reached before the later group pinned")
}
