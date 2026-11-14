package credential

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
)

// PinPolicy says what happens when a configured JSON-LD context cannot be
// fetched while a service starts. The values mirror
// model.JSONLDContextPolicy, which is the operator-facing spelling; this
// package does not import the configuration model.
type PinPolicy string

const (
	// PolicyRequired fails the boot if a context cannot be pinned.
	PolicyRequired PinPolicy = "required"
	// PolicyBestEffort starts without it and keeps trying, reporting the
	// service as not ready meanwhile.
	PolicyBestEffort PinPolicy = "best_effort"
	// PolicyLazy pins nothing and loads a context on first use.
	PolicyLazy PinPolicy = "lazy"
)

// PinGroup is a set of context URLs that are only useful together, with the
// check that becomes answerable once they are all available.
//
// Grouped rather than pinned one at a time because the deferred check is
// per SCOPE: expanding a scope's credential_types needs every one of that
// scope's credential_contexts, so running it when the first of three
// arrives would report terms undefined that the other two define.
type PinGroup struct {
	// Name identifies the configuration this group came from, e.g.
	// "common.credential_metadata.pid".
	Name string

	// Field names the setting within it, e.g. "credential_contexts". It
	// may be empty for a setting that is itself a list of URLs.
	Field string

	// URLs are the contexts to pin.
	URLs []string

	// Consequence completes "... could not be loaded, <consequence>". It
	// says what this service loses, so an issuer and a verifier do not
	// report the same failure as the same loss.
	Consequence string

	// Verify runs once every URL in the group is pinned, and may be nil.
	// It is the check that needs the documents - expanding configured
	// types against the contexts that define them.
	Verify func() error
}

// RetryPolicy bounds the attempts made to fetch a context.
type RetryPolicy struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	BootAttempts    int
}

// backoff returns the wait before attempt n+1, given n attempts have
// failed. Clamped at MaxInterval, which background retries then keep.
func (r RetryPolicy) backoff(failures int) time.Duration {
	initial := r.InitialInterval
	if initial <= 0 {
		initial = time.Second
	}
	multiplier := r.Multiplier
	if multiplier < 1 {
		multiplier = 2
	}
	maxInterval := r.MaxInterval
	if maxInterval <= 0 {
		maxInterval = 5 * time.Minute
	}
	if failures < 1 {
		failures = 1
	}
	// Computed in float so a long outage cannot overflow the duration into
	// a negative wait, which would turn backoff into a spin.
	wait := float64(initial) * math.Pow(multiplier, float64(failures-1))
	if wait >= float64(maxInterval) || math.IsInf(wait, 0) {
		return maxInterval
	}
	return time.Duration(wait)
}

// bootAttempts is how many times the boot pass fetches before the policy
// decides.
func (r RetryPolicy) bootAttempts() int {
	if r.BootAttempts < 1 {
		return 1
	}
	return r.BootAttempts
}

// PinnerOptions configures a Pinner.
type PinnerOptions struct {
	Policy          PinPolicy
	Retry           RetryPolicy
	RefreshInterval time.Duration
	Log             *logger.Log

	// now and sleep are the clock, substituted by tests so a retry
	// schedule can be exercised without waiting for it.
	now   func() time.Time
	sleep func(time.Duration)
}

// Pinner acquires the JSON-LD contexts a deployment is configured with,
// under a policy, and keeps them current.
//
// It owns three things the bare loader does not: WHEN a failure is fatal,
// how long to keep trying, and what the service should tell a readiness
// probe while it is still trying.
type Pinner struct {
	loader *CachingDocumentLoader
	opts   PinnerOptions
	log    *logger.Log

	mu          sync.Mutex
	groups      []*pinGroupState
	nextRefresh time.Time

	stop     chan struct{}
	stopOnce sync.Once
}

// pinGroupState is one group's progress.
type pinGroupState struct {
	group PinGroup

	// pending holds the URLs of this group that are not pinned yet, in
	// configuration order.
	pending []string

	// failures counts consecutive failed attempts, and drives the
	// backoff; nextAttempt is when the background loop may try again.
	failures    int
	nextAttempt time.Time

	lastErr   error
	verified  bool
	verifyErr error
}

// NewPinner returns a Pinner that pins through loader.
func NewPinner(loader *CachingDocumentLoader, opts PinnerOptions) *Pinner {
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.sleep == nil {
		opts.sleep = time.Sleep
	}
	if opts.Log == nil {
		opts.Log = logger.NewSimple("jsonld-contexts")
	}
	if opts.Policy == "" {
		opts.Policy = PolicyRequired
	}
	return &Pinner{
		loader: loader,
		opts:   opts,
		log:    opts.Log,
		stop:   make(chan struct{}),
	}
}

// Pin runs the startup pass over groups.
//
// It returns an error only under PolicyRequired: that is the policy's whole
// content, and the caller turns it into a refused boot. Under
// PolicyBestEffort a context that will not load is logged, recorded as
// pending, and left to the background loop - the service starts and reports
// itself not ready. Under PolicyLazy nothing is fetched here at all.
func (p *Pinner) Pin(ctx context.Context, groups []PinGroup) error {
	if p.opts.Policy == PolicyLazy {
		p.logLazy(groups)
		return nil
	}

	// Published BEFORE anything is attempted, so a readiness probe during
	// the startup pass answers from the real state. Registering them
	// afterwards left HealthProbe with no groups to look at for the whole
	// of the boot, which is to say it reported healthy during precisely
	// the period the service had not yet loaded anything.
	states := make([]*pinGroupState, 0, len(groups))
	for _, group := range groups {
		states = append(states, &pinGroupState{group: group, pending: slices.Clone(group.URLs)})
	}

	p.mu.Lock()
	p.groups = states
	p.mu.Unlock()

	for _, state := range states {
		err := p.attemptWithBootRetries(ctx, state)
		if err == nil {
			continue
		}
		if p.opts.Policy == PolicyRequired {
			return err
		}
		p.log.Warn("starting without a JSON-LD context, and will keep trying",
			"config", state.group.Name, "error", err.Error())
	}

	p.mu.Lock()
	p.nextRefresh = p.refreshDeadline()
	p.mu.Unlock()

	// Under "required" the aggregate decides, not each group in turn. A
	// later group's pin can replace a context an EARLIER group was
	// already verified against, and recheckOtherGroups records that
	// failure where only readiness can see it - so a boot that checked
	// nothing but its own loop would start a service whose first scope no
	// longer checks out. Everything the probe reports is a reason this
	// policy exists.
	if p.opts.Policy == PolicyRequired {
		if err := p.HealthProbe(ctx); err != nil {
			return err
		}
	}
	return nil
}

// logLazy records what the lazy policy chose not to do.
//
// Named explicitly rather than left silent because two guarantees are given
// up here, and an operator reading the log should see both: the documents
// are not pinned, so what is used later is whatever the endpoint serves
// then, and the type-consistency expansion never runs, so a scope whose
// credential_types no context defines will not be reported until a
// credential carrying that type is built.
func (p *Pinner) logLazy(groups []PinGroup) {
	for _, group := range groups {
		if len(group.URLs) == 0 {
			continue
		}
		p.log.Warn("JSON-LD contexts are not pinned and their type consistency is unchecked, because the startup policy is lazy",
			"config", group.Name, "urls", strings.Join(group.URLs, ", "))
	}
}

// attemptWithBootRetries tries a group up to the configured boot attempts,
// waiting the backoff between them.
func (p *Pinner) attemptWithBootRetries(ctx context.Context, state *pinGroupState) error {
	attempts := p.opts.Retry.bootAttempts()
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		// The first attempt may answer from the cache, so a preloaded or
		// already-pinned document costs nothing. Every RETRY bypasses it:
		// pinContext caches a root before it walks that root's
		// references, so a root whose reference failed is left cached
		// with no expiry - and a retry that read the cache would reuse
		// that stale root forever, never seeing the corrected document
		// it is retrying FOR.
		if err = p.attempt(state, attempt > 1); err == nil {
			return nil
		}
		if attempt == attempts {
			break
		}
		wait := p.opts.Retry.backoff(attempt)
		p.log.Warn("a JSON-LD context did not load, retrying",
			"config", state.group.Name, "attempt", attempt, "of", attempts,
			"retry_in", wait.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		default:
		}
		p.opts.sleep(wait)
	}
	return err
}

// attempt pins every URL of a group that is not pinned yet and, once none
// are left, runs the group's deferred check.
//
// Failures are recorded on the state as well as returned, so the readiness
// probe can name what is missing without the caller holding on to errors.
func (p *Pinner) attempt(state *pinGroupState, refresh bool) error {
	p.mu.Lock()
	pending := slices.Clone(state.pending)
	p.mu.Unlock()

	remaining := make([]string, 0, len(pending))
	var problems []error
	wrote := false
	for _, url := range pending {
		urlWrote, err := p.pin(url, refresh)
		wrote = wrote || urlWrote
		if err != nil {
			remaining = append(remaining, url)
			problems = append(problems, p.describe(state.group, url, err))
			continue
		}
		p.log.Info("pinned JSON-LD context", "config", state.group.Name, "url", url)
	}

	// Pinning walks a closure, and closures overlap: one scope's root can
	// reference a context another scope also uses, and a refresh replaces
	// every document it reaches. A group that was verified against the
	// previous copy of a shared context would otherwise keep that verdict
	// for as long as refreshing is off - which it can be.
	if wrote {
		defer p.recheckOtherGroups(state)
	}

	p.mu.Lock()
	state.pending = remaining
	if len(problems) > 0 {
		state.failures++
		state.lastErr = errors.Join(problems...)
		state.nextAttempt = p.opts.now().Add(p.opts.Retry.backoff(state.failures))
		err := state.lastErr
		p.mu.Unlock()
		return err
	}
	state.failures = 0
	state.lastErr = nil
	p.mu.Unlock()

	return p.runVerify(state)
}

// runVerify runs a group's deferred check now that its contexts are
// available.
//
// The result is kept on the state whatever it is: a check that fails after
// the boot has already been allowed to proceed cannot stop the process, so
// readiness is where it has to show up.
func (p *Pinner) runVerify(state *pinGroupState) error {
	if state.group.Verify == nil {
		return nil
	}
	err := state.group.Verify()

	p.mu.Lock()
	state.verified = err == nil
	state.verifyErr = err
	p.mu.Unlock()

	return err
}

// pin acquires one context document and its closure.
// It reports whether the cache was written, which a returned error does
// not settle: pinning stores each document before walking its references.
func (p *Pinner) pin(url string, refresh bool) (bool, error) {
	if refresh {
		return p.loader.RefreshRemoteContext(url)
	}
	return p.loader.PinRemoteContextTracked(url)
}

// describe renders a pin failure in the operator's own vocabulary: the
// setting it came from, and what this service loses by it.
func (p *Pinner) describe(group PinGroup, url string, err error) error {
	consequence := group.Consequence
	if consequence == "" {
		consequence = "so this credential type cannot be processed"
	}
	if group.Field == "" {
		return fmt.Errorf("%s: %q could not be loaded, %s: %w", group.Name, url, consequence, err)
	}
	return fmt.Errorf("%s: %s %q could not be loaded, %s: %w", group.Name, group.Field, url, consequence, err)
}

// Start runs the background loop that retries what is still missing and
// refreshes what is pinned.
//
// A no-op under PolicyLazy, which pins nothing: there is neither a pending
// set to retry nor a pinned set to refresh.
func (p *Pinner) Start(ctx context.Context) {
	if p.opts.Policy == PolicyLazy || !p.hasWork() {
		return
	}
	go p.run(ctx)
}

// hasWork reports whether anything would ever wake the loop: a context
// still to pin, or a refresh interval to honour.
//
// Checked before starting it so a deployment that pinned everything at boot
// and disabled refreshing runs no goroutine at all, rather than one that
// wakes every few minutes to find nothing to do.
func (p *Pinner) hasWork() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.nextRefresh.IsZero() {
		return true
	}
	for _, state := range p.groups {
		if len(state.pending) > 0 {
			return true
		}
	}
	return false
}

// Stop ends the background loop. Safe to call more than once.
func (p *Pinner) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
}

// run is the single background goroutine.
//
// One goroutine rather than one per context: the work is a handful of HTTP
// fetches on a timer, and a goroutine per URL would have to be reaped when
// its context finally pinned.
func (p *Pinner) run(ctx context.Context) {
	for {
		wait := p.untilNextWakeup()
		if wait <= 0 {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.stop:
			timer.Stop()
			return
		case <-timer.C:
			p.tick(ctx)
		}
	}
}

// untilNextWakeup is how long until the soonest retry or refresh is due.
func (p *Pinner) untilNextWakeup() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.opts.now()
	next := time.Time{}
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	for _, state := range p.groups {
		if len(state.pending) > 0 {
			consider(state.nextAttempt)
		}
	}
	consider(p.nextRefresh)

	if next.IsZero() {
		// Nothing pending and refreshing disabled. Wake rarely rather
		// than never, so a group that gains a pending URL later - which
		// only a refresh failure can do - is still picked up.
		return p.opts.Retry.backoff(math.MaxInt32)
	}
	if wait := next.Sub(now); wait > 0 {
		return wait
	}
	return 0
}

// tick does one pass of due work: retry every group still missing a
// context, then refresh the pinned ones if the interval has elapsed.
//
// Exported behaviour is only through run, but tests drive tick directly so
// a schedule can be exercised without real time passing.
func (p *Pinner) tick(ctx context.Context) {
	now := p.opts.now()

	p.mu.Lock()
	due := make([]*pinGroupState, 0, len(p.groups))
	for _, state := range p.groups {
		if len(state.pending) > 0 && !state.nextAttempt.After(now) {
			due = append(due, state)
		}
	}
	refreshDue := !p.nextRefresh.IsZero() && !p.nextRefresh.After(now)
	if refreshDue {
		p.nextRefresh = p.refreshDeadline()
	}
	p.mu.Unlock()

	for _, state := range due {
		// attempt runs the group's deferred check itself once nothing is
		// pending, so the two failures it can return are told apart by
		// what is left pending rather than by verifying a second time.
		// Bypasses the cache, for the reason attemptWithBootRetries
		// gives: a background retry exists to re-reach the source.
		err := p.attempt(state, true)

		p.mu.Lock()
		stillPending := len(state.pending) > 0
		p.mu.Unlock()

		switch {
		case stillPending:
			p.log.Warn("a JSON-LD context is still unavailable",
				"config", state.group.Name, "error", err.Error())
		case err != nil:
			p.log.Error(err, "a JSON-LD context loaded but the types configured against it do not check out",
				"config", state.group.Name)
		default:
			p.log.Info("a JSON-LD context that was unavailable at startup is now pinned",
				"config", state.group.Name)
		}
	}

	if refreshDue {
		p.refreshAll(ctx)
	}
}

// refreshAll re-fetches every group whose contexts are all pinned.
//
// A group with something still pending is left to the retry path above
// instead: refreshing half a group would re-fetch the documents that are
// present and say nothing about the one that is not.
func (p *Pinner) refreshAll(_ context.Context) {
	p.mu.Lock()
	groups := slices.Clone(p.groups)
	p.mu.Unlock()

	for _, state := range groups {
		p.mu.Lock()
		pending := len(state.pending)
		p.mu.Unlock()
		if pending > 0 {
			continue
		}

		var problems []error
		replaced := false
		for _, url := range state.group.URLs {
			// The write flag is taken whatever the outcome: a refresh
			// that fails on a reference has ALREADY replaced the
			// documents above it, so treating a failed refresh as "no
			// change" would leave the group's verdict describing
			// documents the cache no longer holds.
			urlReplaced, err := p.pin(url, true)
			replaced = replaced || urlReplaced
			if err != nil {
				problems = append(problems, p.describe(state.group, url, err))
				continue
			}
		}

		if len(problems) > 0 {
			// Not recorded as pending: the previously pinned copy is
			// still in the cache and still serving, so the service is
			// not degraded and should not report itself unready.
			p.log.Warn("refreshing a JSON-LD context failed, keeping the copy already pinned",
				"config", state.group.Name, "error", errors.Join(problems...).Error())
		} else {
			p.log.Info("refreshed JSON-LD contexts", "config", state.group.Name)
		}

		// Re-checked whenever ANY document was replaced, including a
		// refresh that then failed on a later URL of the group. That
		// leaves the cache holding some fresh documents beside some old
		// ones - a combination nothing has ever expanded the configured
		// types against. Skipping the check there would keep reporting
		// the verdict earned by a set that is no longer the set in use.
		if replaced {
			p.reportVerify(state)
			p.recheckOtherGroups(state)
		}
	}
}

// recheckOtherGroups re-runs the deferred check of every OTHER group whose
// contexts are all pinned, after documents have been replaced.
//
// Conservative on purpose: it re-checks every fully pinned group rather
// than working out which closures overlapped. Expansion is cheap, the
// groups are a handful of scopes, and this runs at most once per refresh
// or retry - whereas getting an overlap calculation subtly wrong leaves a
// scope reporting ready against a context it was never checked against.
func (p *Pinner) recheckOtherGroups(changed *pinGroupState) {
	p.mu.Lock()
	groups := slices.Clone(p.groups)
	p.mu.Unlock()

	for _, state := range groups {
		if state == changed || state.group.Verify == nil {
			continue
		}
		p.mu.Lock()
		pending := len(state.pending)
		p.mu.Unlock()
		if pending > 0 {
			continue
		}
		if err := p.runVerify(state); err != nil {
			p.log.Error(err, "a shared JSON-LD context changed and this scope no longer checks out",
				"config", state.group.Name)
		}
	}
}

// reportVerify runs a group's deferred check and logs a failure, which only
// readiness can act on at this point.
func (p *Pinner) reportVerify(state *pinGroupState) {
	if err := p.runVerify(state); err != nil {
		p.log.Error(err, "a JSON-LD context loaded but the types configured against it do not check out",
			"config", state.group.Name)
	}
}

// refreshDeadline is when the next refresh falls due, or the zero time when
// refreshing is disabled.
func (p *Pinner) refreshDeadline() time.Time {
	if p.opts.RefreshInterval <= 0 {
		return time.Time{}
	}
	return p.opts.now().Add(p.opts.RefreshInterval)
}

// HealthProbe reports the Pinner as unhealthy while any configured context
// is still missing, or while a deferred check against one has failed.
//
// Fails CLOSED, and names what is wrong. A verifier that starts without a
// context cannot canonicalize presentations of that credential type, so
// reporting ready would put it into a load balancer as though it could.
// Under PolicyLazy nothing is pending by construction and this always
// passes, which is what choosing lazy asks for.
func (p *Pinner) HealthProbe(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var waiting []string
	var failed []error
	for _, state := range p.groups {
		if len(state.pending) > 0 {
			waiting = append(waiting, fmt.Sprintf("%s (%s)", strings.Join(state.pending, ", "), state.group.Name))
			continue
		}
		if state.verifyErr != nil {
			failed = append(failed, state.verifyErr)
			continue
		}
		// A group with a deferred check is ready only once that check
		// has PASSED, not merely once its contexts are pinned. attempt
		// clears pending and releases the lock before running Verify, so
		// a probe landing in that window saw no pending URLs and a
		// verifyErr still nil - and reported a service healthy a moment
		// before the check it depends on failed. Fails closed.
		if state.group.Verify != nil && !state.verified {
			waiting = append(waiting, fmt.Sprintf("the configured types of %s are not checked against their contexts yet", state.group.Name))
		}
	}

	if len(waiting) > 0 {
		return fmt.Errorf("waiting for JSON-LD contexts: %s", strings.Join(waiting, "; "))
	}
	if len(failed) > 0 {
		return errors.Join(failed...)
	}
	return nil
}

// Pending returns the contexts that are configured but not yet pinned, for
// operator-facing reporting.
func (p *Pinner) Pending() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var out []string
	for _, state := range p.groups {
		out = append(out, state.pending...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// globalPinner holds the Pinner this process built at startup, so the
// service's readiness handler can report on it without configuration being
// threaded through every constructor between the two.
var (
	globalPinnerMu sync.RWMutex
	globalPinner   *Pinner
)

// SetGlobalPinner records the process-wide Pinner. Called once, from
// configuration setup.
func SetGlobalPinner(p *Pinner) {
	globalPinnerMu.Lock()
	defer globalPinnerMu.Unlock()
	globalPinner = p
}

// GlobalPinner returns the process-wide Pinner, or nil when this service
// resolves no contexts - the apigw and the registry never build one.
func GlobalPinner() *Pinner {
	globalPinnerMu.RLock()
	defer globalPinnerMu.RUnlock()
	return globalPinner
}
