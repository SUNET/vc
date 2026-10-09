package zkcircuit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Wire-shape constraints an issuer has to honour are published per circuit
// version in the catalog's params. Today there is exactly one:
//
//	saltBytes - the length, in bytes, of every IssuerSignedItem's `random`
//	salt that the circuit's digest-ID extraction assumes.
//
// It is a property of the CIRCUIT BUILD, not of any credential schema:
// zk-cred-vega bakes DIGEST_ID_OFFSET_BYTES into its R1CS at setup() time,
// and a credential whose salt is any other length shifts every field out of
// position and fails verification with InvalidSumcheckProof on every claim.
// Before the catalog published it, the number had to be hand-copied into
// each schema, where nothing could notice it going stale - which is the
// defect this resolves (SUNET/vc#723, sirosfoundation/go-zk-circuits#29).
const (
	// ParamSaltBytes is the catalog params key carrying the above.
	ParamSaltBytes = "saltBytes"

	// StatusActive is the only Status an issuer may build for. A
	// deprecated circuit's constraints describe credentials that should no
	// longer be minted, and an entry with any other status - including an
	// empty one - is not something to guess about.
	StatusActive = "active"
)

// MinSaltBytes and MaxSaltBytes bound a catalog-published salt length.
//
// The value reaches make([]byte, n) and is signed by the issuer into every
// credential, so it is read from a remote, configurable source and must be
// bounded here rather than trusted. The window is deliberately wide: the
// point of resolving from the catalog is that the circuit decides, so
// anything a plausible circuit could want has to fit. It is not a
// restatement of "32" - pinning that here would reintroduce exactly the
// hand-copied constant this package exists to remove.
const (
	MinSaltBytes = 8
	MaxSaltBytes = 64
)

// SystemConstraints is what the catalog publishes about one ZK proof
// system's currently-active circuits.
type SystemConstraints struct {
	// System is the catalog's System value, e.g. "vega-mc" or "longfellow".
	System string
	// CircuitIDs are the active circuits the constraints were read from,
	// in catalog order - carried so a log line or an error can name them.
	CircuitIDs []string
	// SaltBytes is the required IssuerSignedItem salt length, or 0 when no
	// active circuit for this system publishes one. Zero means "this
	// system states no salt constraint", NOT "zero bytes": longfellow
	// publishes none and is served by the package's default per-element
	// sizing.
	SaltBytes int
}

// ActiveCircuits returns the manifest's published, active circuits for
// system, in manifest order.
//
// docType, when non-empty, narrows to circuits that declare it. A circuit
// declaring no docTypes at all is NOT assumed to apply to every document
// type - it is skipped. An unscoped entry is a catalog that has not said
// what the circuit is for, and inferring "all" from silence is how a
// constraint meant for an mDL ends up applied to something else.
func (m *Manifest) ActiveCircuits(system, docType string) []CircuitDescriptor {
	if m == nil {
		return nil
	}
	var out []CircuitDescriptor
	for _, c := range m.Circuits {
		if !c.Published || c.Status != StatusActive {
			continue
		}
		if !strings.EqualFold(c.System, system) {
			continue
		}
		if docType != "" && !declaresDocType(&c, docType) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func declaresDocType(c *CircuitDescriptor, docType string) bool {
	for _, d := range c.DocTypes {
		if d == docType {
			return true
		}
	}
	return false
}

// knowsSystem reports whether the manifest carries any circuit naming
// system, regardless of its status, published flag, or doctype. It
// separates a system the catalog has never carried - "not published yet" -
// from one whose circuits are all deprecated, unpublished, or scoped to
// other doctypes, which is a withdrawal rather than a gap.
func (m *Manifest) knowsSystem(system string) bool {
	if m == nil {
		return false
	}
	for _, c := range m.Circuits {
		if strings.EqualFold(c.System, system) {
			return true
		}
	}
	return false
}

// requiresSaltBytes reports whether a system's active circuits MUST publish
// a saltBytes constraint. Vega bakes DIGEST_ID_OFFSET_BYTES into its R1CS at
// setup() time, so catalog v1 carries the length on every published Vega
// entry; an absent value there is a stale/pre-metadata or malformed
// manifest, not a system that opts into the package's default per-element
// sizing the way longfellow does. Longfellow and anything else published
// without the key keep the absent-is-default behaviour.
func requiresSaltBytes(system string) bool {
	return strings.HasPrefix(strings.ToLower(system), "vega")
}

// ErrNoActiveCircuit is returned when a named system has no published,
// active circuit in the manifest for the document type in question.
var ErrNoActiveCircuit = errors.New("no active circuit")

// ErrUnknownSystem is returned when the catalog carries no circuit naming a
// system at ALL - under any status, published flag, or doctype. It is the
// "not published yet" case, kept apart from ErrNoActiveCircuit, which means
// the catalog knows the system but has withdrawn its circuits, left them
// unpublished, or scoped them to other doctypes. Only the former is a gap a
// pinned fallback may stand in for: issuing against a system whose support
// the catalog deliberately removed, or a doctype it does not serve, breaks
// the active-circuit requirement rather than papering over a catalog that
// cannot answer.
var ErrUnknownSystem = errors.New("unknown zk system")

// ErrCatalogUnavailable wraps a failure to OBTAIN a manifest at all - the
// catalog is unreachable, or the resolver has never reached it. It is kept
// distinct from a constraint refusal (an incompatible or malformed answer
// the catalog actually returned) so a caller can fall back to a pinned
// value when the catalog cannot answer, without also masking an answer it
// gave that must not be issued against. A cancelled request is deliberately
// NOT wrapped in it.
var ErrCatalogUnavailable = errors.New("zk circuit catalog unavailable")

// Constraints resolves one system's currently-active wire-shape
// constraints for docType.
//
// Fails closed in both directions: a system the catalog has no active
// circuit for is an error rather than "no constraint", and active circuits
// that disagree with each other are an error rather than a pick.
func (m *Manifest) Constraints(system, docType string) (SystemConstraints, error) {
	circuits := m.ActiveCircuits(system, docType)
	if len(circuits) == 0 {
		if !m.knowsSystem(system) {
			return SystemConstraints{}, fmt.Errorf("%w %q", ErrUnknownSystem, system)
		}
		return SystemConstraints{}, fmt.Errorf("%w for zk system %q and doctype %q", ErrNoActiveCircuit, system, docType)
	}

	resolved := SystemConstraints{System: system}
	// saltFrom records which circuit each distinct value came from, so a
	// disagreement can be reported as the catalog inconsistency it is
	// instead of "expected 32, got 16". unconstrained records the ones
	// that publish no length at all, which is a constraint of its own -
	// see below.
	saltFrom := map[int][]string{}
	var unconstrained []string

	for _, c := range circuits {
		resolved.CircuitIDs = append(resolved.CircuitIDs, c.ID)

		salt, ok := c.ParamInt(ParamSaltBytes)
		if !ok {
			// A key that is PRESENT but unreadable - "32.0", an object, a
			// JSON null - is a constraint nobody can honour, not an
			// absent one. ParamInt cannot tell the two apart, and reading
			// the second as the first fails OPEN: resolution falls back to
			// the package default and mints credentials this very circuit
			// cannot verify.
			if c.HasParam(ParamSaltBytes) {
				return SystemConstraints{}, fmt.Errorf(
					"circuit %q publishes %s as %#v, which is not an integer - refusing rather than treating it as no constraint",
					c.ID, ParamSaltBytes, c.Params[ParamSaltBytes])
			}
			// Genuinely absent: this circuit states no salt constraint.
			// Legitimate on its own - longfellow publishes none - but NOT
			// something to skip past either: see the refusal below.
			unconstrained = append(unconstrained, c.ID)
			continue
		}
		if salt < MinSaltBytes || salt > MaxSaltBytes {
			return SystemConstraints{}, fmt.Errorf(
				"circuit %q publishes %s %d, outside the accepted range [%d, %d]",
				c.ID, ParamSaltBytes, salt, MinSaltBytes, MaxSaltBytes)
		}
		saltFrom[salt] = append(saltFrom[salt], c.ID)
	}

	switch {
	case len(saltFrom) == 0:
		// Every active circuit is unconstrained. For a system that uses
		// the package's default per-element sizing (longfellow) that is a
		// constraint of its own and SaltBytes stays 0. For one that
		// REQUIRES the length (vega), an absent value is a stale,
		// pre-metadata or malformed manifest, not a licence to default:
		// reading it as "no constraint" fails open and mints 16/8-byte
		// salts the circuit cannot verify. Refuse rather than default.
		if requiresSaltBytes(system) {
			sort.Strings(unconstrained)
			return SystemConstraints{}, fmt.Errorf(
				"zk system %q requires %s but its active circuits (%s) publish none - refusing rather than defaulting to per-element sizing the circuit cannot verify",
				system, ParamSaltBytes, strings.Join(unconstrained, ", "))
		}

	case len(saltFrom) == 1 && len(unconstrained) == 0:
		for salt := range saltFrom {
			resolved.SaltBytes = salt
		}

	case len(unconstrained) > 0:
		// The same incompatibility SaltBytes refuses ACROSS systems,
		// one level down and inside a single one. Publishing no length
		// does not mean "any length will do": it means the circuit
		// constrains the item some other way - zk-cred-longfellow's total
		// IssuerSignedItem ceiling - which per-element sizing is what
		// satisfies. A credential carries one salt per item, so a system
		// whose active circuits want both cannot be issued for, and
		// picking the explicit value would mint credentials that fail
		// against the circuit that was skipped.
		sort.Strings(unconstrained)
		return SystemConstraints{}, fmt.Errorf(
			"active circuits for zk system %q disagree about %s: %s publish none and need per-element sizing, while %s",
			system, ParamSaltBytes, strings.Join(unconstrained, ", "), describeDisagreement(saltFrom))

	default:
		return SystemConstraints{}, fmt.Errorf(
			"active circuits for zk system %q disagree about %s: %s",
			system, ParamSaltBytes, describeDisagreement(saltFrom))
	}

	return resolved, nil
}

// SaltBytes resolves the one IssuerSignedItem salt length that every named
// system's active circuits agree on, for docType.
//
// Returns 0 when NO named system publishes a constraint, which leaves the
// caller on its own default per-element sizing.
//
// Two kinds of disagreement, both refusals, because a credential carries
// one salt per item and no credential can satisfy two answers:
//
//   - different lengths. Obvious.
//   - some systems publishing a length and others not. NOT obvious, and
//     the one worth spelling out: publishing nothing does not mean "any
//     length will do". zk-cred-longfellow publishes no saltBytes because
//     what it constrains is the TOTAL IssuerSignedItem size (~119 bytes),
//     which is why this package sizes salts per element - 16 bytes for a
//     claim, 8 for pseudonym_seed, whose value is itself 32 bytes. Giving
//     every item Vega's uniform 32 blows that ceiling for exactly the
//     items the smaller default exists for. So "longfellow + vega-mc"
//     resolves to neither 32 nor the default: it is a schema that cannot
//     be issued, and saying so is the entire point of resolving this from
//     the catalog instead of letting someone write 32 into the schema and
//     find out at presentation time.
//
// The schema then has to name only the system it is actually for - which
// for a dual-system deployment means two schemas, not one.
func (m *Manifest) SaltBytes(systems []string, docType string) (int, error) {
	if len(systems) == 0 {
		return 0, errors.New("no zk systems named")
	}

	saltFrom := map[int][]string{}
	var defaultSized []string
	for _, system := range systems {
		c, err := m.Constraints(system, docType)
		if err != nil {
			return 0, err
		}
		if c.SaltBytes == 0 {
			defaultSized = append(defaultSized, system)
			continue
		}
		saltFrom[c.SaltBytes] = append(saltFrom[c.SaltBytes], system)
	}

	if len(saltFrom) == 0 {
		return 0, nil
	}
	if len(saltFrom) == 1 && len(defaultSized) == 0 {
		for salt := range saltFrom {
			return salt, nil
		}
	}

	if len(defaultSized) > 0 {
		sort.Strings(defaultSized)
		return 0, fmt.Errorf(
			"zk systems %s publish no %s and need this package's per-element sizing, while %s - one credential carries one salt per item, so a schema cannot serve both",
			strings.Join(defaultSized, ", "), ParamSaltBytes, describeDisagreement(saltFrom))
	}
	return 0, fmt.Errorf(
		"zk systems %s require different %s: %s - one credential carries one salt per item, so a schema cannot serve both",
		strings.Join(systems, ", "), ParamSaltBytes, describeDisagreement(saltFrom))
}

// describeDisagreement renders a value -> who-said-it map deterministically,
// so the same catalog inconsistency always produces the same message.
// Reads as "32 (vega-mc)" or "16 (a) vs 32 (b)".
func describeDisagreement(by map[int][]string) string {
	values := make([]int, 0, len(by))
	for v := range by {
		values = append(values, v)
	}
	sort.Ints(values)

	parts := make([]string, 0, len(values))
	for _, v := range values {
		names := append([]string(nil), by[v]...)
		sort.Strings(names)
		parts = append(parts, fmt.Sprintf("%d (%s)", v, strings.Join(names, ", ")))
	}
	return strings.Join(parts, " vs ")
}

// DefaultResolverTTL is how long a Resolver reuses a fetched manifest.
//
// Circuit publication is a human-scale event - a new Vega revision lands
// every few months - so this is about not making the catalog a dependency
// of every issuance, not about propagation speed. An operator who has just
// published a circuit and wants it picked up now restarts the service.
const DefaultResolverTTL = time.Hour

// DefaultResolverRetryInterval is how long the resolver keeps serving a
// stale manifest after a refresh fails, before trying the catalog again.
//
// Without it a failed refresh left the manifest expired, so EVERY
// subsequent issuance attempted its own fetch - while holding the
// resolver's mutex, which is what makes the fetch single-flight on the
// happy path. One unreachable catalog therefore serialized every
// credential behind a 30-second HTTP timeout, turning a cache that was
// supposed to absorb an outage into the thing amplifying it.
//
// A minute: short enough that a catalog coming back is picked up promptly,
// long enough that an outage costs one request a minute rather than all of
// them.
const DefaultResolverRetryInterval = time.Minute

// Resolver answers circuit-constraint questions from a cached manifest.
//
// Issuance is on a request path and must not turn into a catalog round
// trip per credential, but it must also not be taken down by the catalog
// being briefly unreachable. So: refresh on expiry, and when a refresh
// fails, keep serving the last manifest that parsed and say that it is
// stale. The one thing it will not do is answer from nothing - a resolver
// that has never successfully fetched returns the fetch error, because the
// alternative is issuing credentials shaped by a guess.
type Resolver struct {
	// Client fetches the manifest. Required.
	Client *Client
	// TTL is how long a fetched manifest is reused. Zero means
	// DefaultResolverTTL.
	TTL time.Duration
	// RetryInterval is how long a failed refresh is backed off for while
	// the previous manifest is served stale. Zero means
	// DefaultResolverRetryInterval.
	RetryInterval time.Duration
	// Now is the clock, for tests. Zero value means time.Now.
	Now func() time.Time

	mu        sync.Mutex
	manifest  *Manifest
	fetchedAt time.Time
	// lastFailure is when a refresh last failed, cleared on the next
	// success. fetchedAt only moves on success, so without this an expired
	// manifest plus an unreachable catalog means a fetch attempt per call.
	lastFailure time.Time
	// coldErr is the failure from a resolver that has never successfully
	// fetched, replayed for the retry window so a cold catalog outage
	// costs one fetch a minute rather than one per request.
	coldErr error
}

// NewResolver returns a Resolver over c.
func NewResolver(c *Client) *Resolver {
	return &Resolver{Client: c}
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) ttl() time.Duration {
	if r.TTL > 0 {
		return r.TTL
	}
	return DefaultResolverTTL
}

func (r *Resolver) retryInterval() time.Duration {
	if r.RetryInterval > 0 {
		return r.RetryInterval
	}
	return DefaultResolverRetryInterval
}

// Manifest returns the cached manifest, refreshing it if it has aged past
// the TTL. stale is true when the refresh failed and the returned manifest
// is the previous one; the fetch error is reported through stale rather
// than returned, since the caller got a usable answer. An error is
// returned only when there is nothing cached to fall back to.
func (r *Resolver) Manifest(ctx context.Context) (manifest *Manifest, stale bool, err error) {
	if r == nil || r.Client == nil {
		return nil, false, fmt.Errorf("%w: resolver has no catalog client", ErrCatalogUnavailable)
	}

	// The lock is held across the fetch on purpose: it makes the refresh
	// single-flight, so a cold start serving a burst of requests performs
	// one catalog round trip rather than one per request. The retry
	// backoff below is what stops that from turning an unreachable catalog
	// into every request waiting on its own timeout.
	r.mu.Lock()
	defer r.mu.Unlock()

	// A cancelled or expired request must not be answered from cache: the
	// caller is already gone, and handing back a usable salt length here
	// lets an expired issuance continue into signing. Guards every cached
	// return below, and is rechecked after the fetch.
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	now := r.now()
	if r.manifest != nil && now.Sub(r.fetchedAt) < r.ttl() {
		return r.manifest, false, nil
	}
	if !r.lastFailure.IsZero() && now.Sub(r.lastFailure) < r.retryInterval() {
		if r.manifest != nil {
			// A refresh failed recently and the previous manifest is
			// still usable. Serve it and say so, rather than queueing
			// behind another fetch that is probably about to fail the
			// same way.
			return r.manifest, true, nil
		}
		if r.coldErr != nil {
			// Never reached the catalog, and the last attempt failed
			// within the window. Replay that failure instead of making
			// this caller - and everyone behind the mutex - wait out
			// another fetch.
			return nil, false, r.coldErr
		}
	}

	fetched, fetchErr := r.Client.FetchManifest(ctx)
	if fetchErr != nil {
		// A cancelled or timed-out REQUEST says nothing about the
		// catalog, and the backoff state is shared by every caller. Leave
		// that state untouched - one client hanging up during a fetch must
		// not make every subsequent issuance replay the cancellation for
		// the retry interval, against a catalog that is perfectly healthy -
		// but do NOT convert the cancellation into a successful stale
		// answer either: the caller asked with a dead context and has to
		// see it, or an expired request still mints a credential.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, false, fetchErr
		}

		r.lastFailure = r.now()
		if r.manifest != nil {
			return r.manifest, true, nil
		}
		// Nothing cached to fall back to. The error is REMEMBERED and
		// replayed for the retry window all the same: a resolver that has
		// never reached the catalog has no manifest to protect, but it
		// still has the request path. Without this every issuance took
		// the mutex in turn and repeated the client's 30-second fetch, so
		// a cold start against an unreachable catalog serialized the
		// whole deployment behind one timeout after another - including
		// schemas that pin zk_salt_bytes, which fall back to the pin only
		// AFTER the error arrives, and so paid 30 seconds each for an
		// answer they already had.
		r.coldErr = fmt.Errorf("%w: %w", ErrCatalogUnavailable, fetchErr)
		return nil, false, r.coldErr
	}

	r.manifest = fetched
	r.fetchedAt = r.now()
	r.lastFailure = time.Time{}
	r.coldErr = nil
	return r.manifest, false, nil
}

// SaltBytes resolves the required salt length for systems and docType.
// stale reports that the answer came from a manifest the resolver could
// not refresh - worth logging, not worth refusing to issue over.
func (r *Resolver) SaltBytes(ctx context.Context, systems []string, docType string) (salt int, stale bool, err error) {
	manifest, stale, err := r.Manifest(ctx)
	if err != nil {
		return 0, false, err
	}
	salt, err = manifest.SaltBytes(systems, docType)
	if err != nil {
		return 0, stale, err
	}
	return salt, stale, nil
}
